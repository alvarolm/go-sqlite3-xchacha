# Optimization notes

Optimization paths that have been analyzed but not yet (or never) applied.
Two kinds of entries:

- **Declined** — ideas that look attractive but carry a cost the project has
  decided not to pay. Recorded so a contributor doesn't redo the analysis
  blind.
- **Deferred** — real wins with a known design, just not yet prioritized.
  Detailed enough that a contributor can pick one up and implement it.

## Declined: vendoring `chacha20poly1305` in-tree — high maintenance burden

**What it is.** Fork or vendor `golang.org/x/crypto/chacha20poly1305` into
this module so the unexported `xchacha20poly1305` struct becomes nameable.
The `aead` field on `mainDBFile` and `auxFile` would change from
`cipher.AEAD` (interface) to `*xchacha20poly1305` (concrete pointer).

**Why it's tempting.** It is the only path that lets the Go compiler
devirtualize `f.aead.Seal(...)` / `f.aead.Open(...)`. Projected **~5–10 %
ns/op** improvement on AEAD-bound microbenchmarks (the inner loop of
`mainDBFile.WriteAt`, `auxFile.sealBlock`, `auxFile.readBlock`).

**Why we declined.**

- **Security-update tracking.** XChaCha20-Poly1305 is a moving target:
  upstream `x/crypto` ships constant-time fixes, side-channel hardening,
  and ARM/AMD64 assembly improvements. Vendoring means we own the
  commitment to track every CVE and assembly-level optimisation, forever,
  on a piece of code we have no expertise in maintaining.
- **Code volume.** ~1500 lines of cryptographic code (assembly + Go
  fallbacks) move into the module. Larger review surface for every
  contributor; CI matrix grows with every new architecture.
- **Cost/benefit ratio.** The ~5–10 % AEAD-microbench gain attenuates
  rapidly through SQLite-internal page management, WAL I/O, and the
  `database/sql` plumbing. Measured on the benchmark suite at
  `/home/alvarolm/temp/sqlite_tests`, the end-to-end win on
  `InsertSingle_File` is projected at closer to **~1–2 %**.
- **Better alternatives exist.** Two optimizations target the WAL append
  pattern directly and project larger end-to-end wins without touching the
  AEAD primitive at all:
  - **Skip `readBlock` past EOF** in `auxFile.WriteAt` — projected −10
    to −18 % on `InsertSingle_File`. See the deferred section below.
  - **Last-block cache** in `auxFile` (the trailing partial block of WAL
    frame N is the leading partial block of frame N+1) — projected
    additional −5 to −15 %.

**If you still want to do this**, open an issue first and link it from
this section. The following are required before a vendoring PR can merge:

1. A documented policy for tracking upstream `x/crypto` security commits:
   frequency, owner, sign-off process.
2. CI that diffs the vendored copy against a pinned upstream tag and
   fails the build on drift.
3. End-to-end benchmark numbers (not just AEAD microbenchmarks) on at
   least `BenchmarkInsertSingle_File` and `BenchmarkInsertBatchTx_File`
   from the bench suite at `/home/alvarolm/temp/sqlite_tests`, showing
   the gain after the cheaper alternatives above have already been applied.

**Background.** `chacha20poly1305.NewX` returns `cipher.AEAD` (an interface
from `crypto/cipher`); the concrete `xchacha20poly1305` struct in
`x/crypto` is unexported, so we cannot get a nameable concrete value out of
the upstream library. After the per-call `plain` buffer was hoisted to a
struct field on `auxFile` (the `f.scratch` field in `auxfile.go`), the
escape-related rationale for concretizing also went away — the only saving
left from concretizing at this layer is the per-call interface dispatch
itself, which is what motivates the in-tree vendoring proposal.

## Deferred: skip `readBlock` past EOF in `auxFile.WriteAt`

**What it is.** Track the underlying file's physical size in a new
`auxFile.physSize int64` field. In the partial-block branch of
`auxFile.WriteAt`, check `physBlockOff(blockN) >= f.physSize` *before*
calling `readBlock`; if true, the block doesn't exist on disk yet, so
treat it as past-EOF directly (zero the holes, skip the read).

**Why it's tempting.** WAL append always crosses a logical-block
boundary: each WAL frame is 24 B header + 4096 B page = 4120 B written
at offset `32 + N·4120`, none of which are 4096-aligned. So every
`WriteAt(frame)` covers two logical blocks: a leading partial (real read,
genuinely needed) and a trailing partial (always past-EOF, the read is
guaranteed to return EOF). The trailing read is a wasted syscall on
every WAL frame. Profile data on `BenchmarkInsertSingle_File`
(post-`f.scratch` baseline of 70.3 µs/op) shows `readBlock` cumulative
~24 % of total CPU; eliminating roughly half of that is the projected
**−10 to −18 % ns/op** on `InsertSingle_File`. Smaller, similar-shaped
wins on `DeleteOne_File`, `UpdateOne_File`, `InsertBatchTx_File`.
Read-only benches unaffected.

**Why deferred.** Not blocked on anything — no API change, no on-disk
format change, no security-relevant code touched. Simply hasn't been
implemented yet.

**Design.**

The cache invariant is that `f.physSize` must always be **≥ the actual
file size**:

- `physSize > actual` → cache says "block exists" when it doesn't → we
  issue an unnecessary read that returns EOF and falls through to the
  existing EOF branch. **Harmless.**
- `physSize < actual` → cache says "block doesn't exist" when it does →
  we skip the read and zero the scratch, overwriting any preserved data
  with zeros. **Silent data corruption.**

So the cache may only **advance** from observed writes, never shrink
except via the explicit `Truncate` path. Update points:

| Path | Action |
|---|---|
| `openAux` (`api.go`) | Initialize `physSize = file.Size()`. The legacy-format probe at the top of `openAux` already retrieves this value — hoist it out of the `if` and reuse. Conservative `0` on size error. |
| `auxFile.sealBlock` (`auxfile.go`) | After successful `f.File.WriteAt`, advance `physSize` to `max(physSize, physBlockOff(blockN) + physBlockSize)`. |
| `auxFile.Truncate` (`auxfile.go`) | After `f.File.Truncate(physRoundUp(size))` succeeds, set `physSize = physRoundUp(size)`. |
| `auxFile.WriteAt` (the consumer) | In the partial-block branch, check `physBlockOff(blockN) >= f.physSize` before `readBlock`. If true, zero the holes directly. |
| Other paths (`SizeHint`, `ChunkSize`, etc.) | No update. Per the invariant, an underestimating cache in pre-extended regions is safe — those regions hold preallocated zeros that wouldn't decrypt anyway, and overwriting with a fresh-keyed block is functionally identical to a new-block write. |

**Defense in depth.** Keep the existing `case io.EOF, io.ErrUnexpectedEOF:`
branch in `WriteAt`. The cache check should make it dead code, but if a
future change ever introduces a path that extends the file outside our
tracking, the EOF branch remains as a correct fallback rather than turning
into a corruption vector.

**Concurrency.** Each `database/sql` connection has its own VFS file open,
so each `auxFile` has its own `physSize` cache and lives on a single
goroutine at a time. No locking needed.

**Verification before merge.**

1. `go build -gcflags='-m=1' .` — escape map should be unchanged from
   the post-`f.scratch` state (only `mainfile.go:62 hdr` should appear).
2. `go test -race ./...` — every test must pass. Critical regression
   targets: `Test_aux_write_past_eof` (directly stresses the trailing-
   partial past-EOF case), `Test_wal_roundtrip` (catches leading-partial
   corruption from cache-disagreement bugs), `Test_wal_tamper_*` (proves
   the seal is still over the right plaintext), `Test_journal_*`.
3. Bench delta against the bench suite at
   `/home/alvarolm/temp/sqlite_tests`:
   ```
   go test -bench='Insert|Update|Delete|Concurrent' -benchmem -count=10 ./xchacha
   ```
   Expected: `InsertSingle_File` ns/op −10 to −18 %; `DeleteOne_File`
   similar; reads unchanged. B/op and allocs/op essentially unchanged
   (the cache is a single int64 field).
4. Re-profile to confirm `auxFile.readBlock` cumulative drops and
   `f.File.ReadAt` cumulative drops correspondingly.

**Out of scope for this entry.** The "last-block cache" optimization
(see the declined-vendoring section above) is independent and can land
in a separate change. Do this one first — it's strictly smaller and
keeps the diff bisectable.
