# Issues

Findings from comparing this VFS against upstream `ncruces/go-sqlite3/vfs/adiantum`
and `.../vfs/xts`. Ordered by impact.

## 1. `openAux` silent-random-key branch — **FIXED**

**Where:** `api.go` (`openAux`)

**Severity (as triaged):** latent / defense-in-depth. The bug was never
directly reachable: the main-DB guard at `mainfile.go:94` (`ReadAt` returns
`CANTOPEN` for any read beyond the 100-byte probe while `aead == nil`)
caused SQLite to bail before opening any WAL/journal. Verified by
`Test_wal_before_textkey_fails` — no sidecar file was produced on disk.

**Original concern:** When SQLite opened a journal/WAL while the associated
main DB was still awaiting `PRAGMA textkey`/`key`/`hexkey`, `UnwrapFile`
succeeded but `main.auxKey == nil`. The `openAux` code would fall through to
the "standalone aux file" branch and assign a **random** aux key. Writes to
that aux file would be unrecoverable — no other process (or the same
process after reopen) could derive the same random key. Upstream adiantum
/xts return `IOERR_BADKEY` in this case, enforcing the invariant at the
`openAux` layer itself rather than relying on the main-DB guard upstream.

**Resolution:** `openAux` now explicitly distinguishes "main DB present but
unkeyed" (→ `IOERR_BADKEY`) from "no associated main DB" (→ random key for
true standalone transients). The invariant is now enforced locally in
`openAux`, so a future change to the main-DB read guard cannot silently
re-enable the branch. Regression test: `Test_wal_before_textkey_fails` in
`xchacha_test.go`. All existing tests still pass.

## 2. Keystream leak on partial aux writes past EOF — **FIXED**

**Where:** `auxfile.go` (`auxFile.WriteAt`)

**Resolution:** The aux-file format changed from length-preserving XChaCha20
stream cipher (deterministic nonce = HKDF of offset) to XChaCha20-Poly1305
AEAD per 4096-byte logical block, stored as 4136-byte physical blocks with
`[ciphertext | nonce | tag]`. Every write generates a fresh random nonce, so
there is no keystream to leak. Partial-block writes past EOF zero-pad the
plaintext and re-seal with a fresh nonce and tag — the encrypted-zeros
prefix no longer reveals keystream because the nonce is never reused.

## 3. Per-page heap allocations in hot path — **FIXED**

**Where:** `mainfile.go` (`decryptPage`, `WriteAt`) and `auxfile.go`
(`readBlock`, `sealBlock`) carried ~4-5 allocs per page/block on the hot path:
`aad` (24 B, +100 B on page 1), `ctAndTag` (~4072 B), `nonce` (24 B),
and the `Seal` output (~4072 B).

**Resolution:** Added struct-resident scratch buffers on both `mainDBFile`
and `auxFile` (`aadBuf`, `ctTagBuf`) and rewrote the four methods to:
- Build AAD into `aadBuf` (reused across calls).
- Stitch `ct || tag` into `ctTagBuf` (where needed) — replaces the per-op
  heap allocation with a copy into struct storage.
- Generate the nonce directly into `f.buf` at its on-disk slot, skipping a
  separate nonce allocation.
- `Seal` into `ctTagBuf[:0]` and `Open` in place back into the `f.buf`
  ciphertext region — no allocated result slice.

Benchmark results (`go test -bench -benchmem`, `x/crypto@v0.50.0`,
Go 1.24 compiler, escape analysis elides the `x/crypto` internals):

```
Benchmark_main_db_page_encrypt    0 B/op    0 allocs/op
Benchmark_main_db_page_decrypt    0 B/op    0 allocs/op
Benchmark_aux_block_seal          0 B/op    0 allocs/op
Benchmark_aux_block_read          0 B/op    0 allocs/op
```

The "bigger win" layout reorder (`[ct | nonce | tag]` → `[nonce | ct | tag]`)
was considered and dropped: in-place `Seal`/`Open` under the new layout would
land plaintext at `f.buf[nonceSize:]`, but `ReadAt`'s caller expects it at
`f.buf[:usablePerPage]`, forcing a compensating ~4 KB memcpy that erases the
CPU savings. Page 1's 100-byte plaintext header would also make the plaintext
region non-contiguous under the new layout. Revisit only if profiling shows a
memcpy-bound hot path.

## 4. `SectorSize` fallback is not a true LCM — **FIXED**

**Where:** `mainfile.go` (`mainDBFile.SectorSize`) and `auxfile.go`
(`auxFile.SectorSize`)

**Original concern:** When the base VFS reports a sector size that isn't in a
clean divisor/multiple relationship with our crypto block, the wrapper
returned the crypto block size instead of a true LCM. Upstream uses
`util.LCM(base, block)`.

The original example in this doc ("8192-byte disk returns 4096") was wrong —
`s % pageSize == 0` already handled 8192 correctly. The actual misbehavior
was limited to non-power-of-2 sector sizes (e.g., a hypothetical 6144-byte
sector would return 4096 instead of LCM=12288). Real hardware always reports
power-of-2 sector sizes, so the fallback was never triggered in practice,
making this purely academic.

**Resolution:** Added an unexported `lcm(a, b int) int` helper in `xchacha.go`
(Euclid's GCD, returns 0 on non-positive input) and rewrote both
`SectorSize` methods to return `lcm(base, block)`, falling back to the
crypto block size only if the base reports a non-positive sector size.
Upstream's `util.LCM` lives under `internal/util` and isn't importable, so
the helper is reimplemented locally.

## 5. `ATTACH`-ed database keying is undocumented — **FIXED**

**Where:** `api.go` package doc

**Original concern:** Upstream's `adiantum` doc explicitly shows the ATTACH
+ schema-qualified PRAGMA pattern. xchacha's package doc didn't, even though
the code path already works (each `mainDBFile` has its own `Pragma` handler).

**Resolution:** Added an example block to the package doc between the
"existing encrypted database" section and the parameters list. Two patterns
documented because they are NOT interchangeable:

- Existing encrypted DB — key **must** be in the ATTACH URI:

  ```go
  db.Exec(`ATTACH DATABASE 'file:existing.db?vfs=xchacha&textkey=pass' AS other`)
  ```

- Brand-new attached DB — PRAGMA-after-ATTACH works (the file is empty, so
  the EOF probe fires and ATTACH treats the file as a new DB):

  ```go
  db.Exec(`ATTACH DATABASE 'file:new.db?vfs=xchacha' AS other`)
  db.Exec(`PRAGMA other.textkey = 'new passphrase'`)
  ```

Why the distinction: SQLite reads page 1 during ATTACH itself to validate
the schema. For an existing encrypted file with `aead == nil` this read
returns `CANTOPEN` and ATTACH fails before PRAGMA can run. The initial
draft of this doc showed only the PRAGMA-after form and was misleading for
existing files — caught while writing the `Test_attach_independent_keys`
regression test (see issue 7).

## 6. Plaintext header leaks file metadata — **DOCUMENTED (design choice)**

**Where:** `mainfile.go` (bytes 0..100 of page 1 served plaintext, bound as
AAD); `api.go` package doc "Security summary".

**Original concern:** Bytes 0..100 of page 1 are stored in plaintext (SQLite
file header). Bound as AAD so tampering is detected, but readable by anyone.
This leaks: `SQLite format 3\0` magic, page size, reserve_bytes, file change
counter, in-header db size, freelist trunk and count, schema cookie, schema
format number, default cache size, largest root btree page, text encoding,
`user_version`, incremental vacuum mode, `application_id`,
version-valid-for number, and SQLite version number. Upstream adiantum/xts
encrypt this region.

**Resolution:** Documented as an explicit design tradeoff in the `api.go`
package comment's "Security summary" section. The plaintext header is
intentional — it's what makes the key-deferred PRAGMA flow work (empty-file
EOF probe on open, then header-visible page-size/reserve_bytes resolution
before the key is installed). Users for whom the metadata leak is
unacceptable are pointed at upstream adiantum/xts, which encrypt the header
region at the cost of separate key-presence state tracking.

Changing the design would require the same `hbsh == nil` + EOF bookkeeping
upstream uses; not worth the added complexity for this VFS's intended
threat model.

## 7. No test coverage for aux-file path — **FIXED**

**Where:** `xchacha_test.go`

**Original concern:** The three original tests (`Test_roundtrip`,
`Test_wrong_key`, `Test_tamper`) exercised only the main DB file. Missing
coverage: WAL round-trip, rollback journal, transient DB, ordering bug from
issue 1, `VACUUM`, ATTACH with independent keys, crash-and-recover.

**Resolution:** Coverage added incrementally. Current aux-file tests:

| Punch-list item | Test |
|---|---|
| `PRAGMA journal_mode=WAL` round-trip | `Test_wal_roundtrip` |
| Rollback journal + explicit `ROLLBACK` | `Test_rollback_journal_roundtrip` |
| `CREATE TEMP TABLE` (transient DB) | `Test_transient_temp_table` |
| WAL-before-textkey ordering (issue 1) | `Test_wal_before_textkey_fails` |
| `VACUUM` (subjournal + temp-DB swap) | `Test_vacuum_roundtrip` |
| `ATTACH DATABASE` with independent keys | `Test_attach_independent_keys` |

Plus bonus coverage beyond the original punch list:
`Test_wal_tamper_ciphertext`, `Test_wal_tamper_nonce`, `Test_wal_tamper_tag`,
`Test_aux_write_past_eof`, `Test_legacy_aux_format_rejected`.

**Crash-and-recover — punted with rationale:** The aux-file AEAD guarantees
don't change under crash-recover vs. explicit rollback. The existing
rollback + three WAL-tamper + past-EOF + legacy-format tests cover every
aux-file code path a real crash would exercise. True crash-recovery semantics
are SQLite's concern, not the cipher layer's. A faithful test would require
either a SIGKILL-able subprocess runner or intercepting `Sync` on the main
DB file — not worth the complexity for a guarantee SQLite already owns.

**Bonus:** writing `Test_attach_independent_keys` uncovered that the ATTACH
+ PRAGMA pattern originally documented for issue 5 only works for *new*
attached DBs; for existing encrypted files the key must be in the ATTACH
URI. Issue 5's Resolution has been updated accordingly.

## 8. Minor: URI `key` parameter accepts empty string differently than upstream — **FIXED**

**Where:** `api.go` (`openMainDB` URI parsing)

**Original concern:** Upstream adiantum accepts empty `key=` / `hexkey=`
and lets them fall through to `HBSH(key)`, which rejects them on length
(→ `IOERR_BADKEY`). xchacha guarded all three params with `len(t[0]) > 0`,
so an empty URI key was silently ignored and the open deferred to PRAGMA
instead of erroring — divergent from upstream and confusing (a typo like
`?key=` would be a no-op rather than a loud failure).

**Resolution:** Removed the `len > 0` guards on `key` and `hexkey` so an
empty value now surfaces `IOERR_BADKEY` via `setKey` → `Keys` length check.
Kept the guard on `textkey` (also what upstream does): `textkey=` stays
PRAGMA-deferred rather than being KDF'd into a random 32-byte key, which
would silently lock the user out of their own data.

## 9. Observability: `setKey` failures are indistinguishable — **FIXED**

**Where:** `mainfile.go` (`setKey`)

**Original concern:** `setKey` returned `sqlite3.IOERR_BADKEY` for three
distinct conditions — wrong key length, wrong page size in header, and
wrong `reserve_bytes` byte — so a user migrating a DB from a
non-reserve-bytes build would see "bad key" and reasonably conclude the
passphrase was wrong.

**Resolution:** The two format-mismatch cases (`page size` header mismatch
and `reserve_bytes` != 40) now return `sqlite3.NOTADB` ("file opened that
is not a database file"). `IOERR_BADKEY` is reserved for actual key-material
problems (wrong length from `Keys`). A user hitting `NOTADB` on open now
has a clear signal that the file wasn't created by this VFS, separate from
the signal that their passphrase was wrong.

## 10. Pool + URI-key produces malformed file on create — **FIXED**

**Where:** `mainfile.go` (`WriteAt`), `api.go` (docs + `ReserveBytes`).

**Original concern:** With `database/sql` connection pooling, passing the
key via URI parameters (`?hexkey=...`) on a NEW database silently created
a malformed file. Root cause: URI parsing installs the cipher key per
connection, but `reserve_bytes` is a SQLite connection-level setting that
requires a per-connection `FCNTL_RESERVE_BYTES` call (what `ReserveBytes`
does). Without the init hook, the first writer ends up with
`reserve_bytes == 0` in SQLite, so page 1 lands on disk with header byte
20 == 0. Every subsequent pool connection then hits `NOTADB` in `setKey`
while reading the header. A race between pool opens and the first page-1
write explains the intermittent "some workers succeed, others fail"
symptom — connections that opened before any byte 20 == 0 page was
persisted passed `setKey`'s size==0 short-circuit, later ones didn't.

**Resolution:**

1. `mainDBFile.WriteAt` now refuses to write page 1 when header byte 20
   differs from `reserveBytes` (40), returning `IOERR_WRITE`. The malformed
   file can no longer be produced — the trap fails loud at the first
   attempted write instead of surfacing minutes later as `NOTADB` on
   unrelated pool connections.
2. Package doc rewritten: the recommended/supported pattern is now a
   per-connection init hook passed to `driver.Open` that calls
   `xchacha.ReserveBytes` and then `PRAGMA textkey/hexkey/key`. URI-based
   key delivery is described as safe only against a database that was
   already created with the init-hook pattern.
3. `ReserveBytes` godoc rewritten to call out that it's required on every
   connection for creates, and to cross-reference the new `WriteAt` check.
4. Regression test: `Test_concurrent_pool_connections` opens 4 pool
   connections, 16 workers, asserts all succeed end-to-end.
