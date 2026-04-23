# Issues

Findings from comparing this VFS against upstream `ncruces/go-sqlite3/vfs/adiantum`
and `.../vfs/xts`. Ordered by impact.

## 1. `openAux` silently assigns a random key when main DB has no key yet

**Where:** `api.go:147-169` (`openAux`)

**What:** When SQLite opens a journal/WAL while the associated main DB is still
awaiting `PRAGMA textkey`/`key`/`hexkey`, `UnwrapFile` succeeds but
`main.auxKey == nil`. The current code falls through to the "standalone aux
file" branch and assigns a **random** aux key. Any writes to that WAL/journal
are then unrecoverable — no other process (or even the same process after
reopen) can derive the same random key.

Upstream adiantum/xts return `IOERR_BADKEY` in this case, which is the correct
failure mode.

**Realistic trigger:** `PRAGMA journal_mode=WAL` executed before
`PRAGMA textkey=...`. Any statement that causes a journal/WAL open before the
key PRAGMA runs.

**Fix sketch:** Distinguish "main DB present but unkeyed" from "no main DB
associated". Only the latter should get a random key.

```go
if name != nil {
    if main, ok := vfsutil.UnwrapFile[*mainDBFile](name.DatabaseFile()); ok {
        if main.auxKey == nil {
            file.Close()
            return nil, flags, sqlite3.IOERR_BADKEY
        }
        auxKey = main.auxKey
    }
}
if auxKey == nil {
    // truly standalone (name == nil or no main DB attached)
    ...
}
```

## 2. Keystream leak on partial aux writes past EOF

**Where:** `auxfile.go:58-92` (`auxFile.WriteAt`)

**What:** On a partial write that extends past EOF, the block buffer is
zero-padded (`clear(data)`), the caller's bytes are copied in starting at
`off-min`, and the entire block is XORed with the keystream at that offset.
The prefix `[0, off-min)` is encrypted zeros — revealing the keystream for
that region. Combined with the deterministic per-offset nonce
(`HKDF(aux_key, offset)`), any later write that legitimately populates that
prefix leaks its plaintext via XOR with the observed encrypted zeros.

**Fix options:**
- Track the real file size and refuse to write past EOF unless the write
  fully covers the new tail.
- Or, document this more loudly as a known weakness of the stream construction
  (upstream adiantum is length-preserving and doesn't hit this because the
  HBSH cipher always consumes the whole block).

## 3. Per-page heap allocations in hot path

**Where:** `mainfile.go:151, 161, 201, 208` (`decryptPage`, `WriteAt`)

**What:** Every page encrypt/decrypt allocates:
- `aad` via `append([]byte(nil), ...)` (24 B, page 1 also +100 B header)
- `ctAndTag` via `make([]byte, 0, ...)` (4072 B)
- `nonce` via `make([]byte, nonceSize)` (24 B) on write

For a 1 GiB DB that's ~262 k page-level allocations per full scan.

**Fix:** Put scratch buffers on `mainDBFile`:

```go
type mainDBFile struct {
    ...
    aadBuf     [8 + headerPlaintext]byte
    ctTagBuf   [usablePerPage + tagSize]byte
    nonceBuf   [nonceSize]byte
}
```

**Bigger win:** Reorder the on-disk page layout from
`[ciphertext | nonce | tag]` to `[nonce | ciphertext | tag]`. Then ciphertext
and tag are contiguous in `f.buf`, matching `AEAD.Seal`/`Open`'s native
`ciphertext||tag` layout. `ctAndTag` goes away entirely. This is a
file-format change, so do it before the format is considered stable.

## 4. `SectorSize` fallback is not a true LCM

**Where:** `mainfile.go:238-247` and `auxfile.go:98-108`

**What:** When the base VFS reports a sector size that doesn't divide evenly
into `pageSize`, the wrapper returns `pageSize` instead of a true common
multiple. Upstream uses `util.LCM(base, block)`.

For 512/4096 disks this is fine. For an 8192-byte-sector disk the correct
answer is 8192, not 4096. Mostly academic — but upstream already imports
`util.LCM` (the package lives at `github.com/ncruces/go-sqlite3/internal/util`
which is internal-only, so this may need reimplementation).

## 5. `ATTACH`-ed database keying is undocumented

**Where:** `api.go` package doc

**What:** Upstream's `adiantum` doc explicitly shows:

```sql
ATTACH DATABASE 'demo.db' AS demo;
PRAGMA demo.textkey='...';
```

xchacha's package doc doesn't. The code path works (each `mainDBFile` has its
own `Pragma` handler), but users won't discover it.

**Fix:** Add the snippet to the `api.go` package comment.

## 6. Plaintext header leaks file metadata

**Where:** `mainfile.go:82-100` (design choice, not a bug)

**What:** Bytes 0..100 of page 1 are stored in plaintext (SQLite file header).
Bound as AAD so tampering is detected, but readable by anyone. This leaks:
`SQLite format 3\0` magic, page size, reserved-bytes value, file change
counter, in-header db size, first freelist trunk, freelist count,
schema cookie, schema format number, default cache size, largest root btree
page, text encoding, `user_version`, incremental vacuum mode,
`application_id`, version-valid-for number, SQLite version number.

Upstream adiantum/xts encrypt this region.

**Decision point:** Document the tradeoff explicitly in `api.go`'s "Security
summary", or change the design to encrypt the header (would require tracking
key-presence state separately, since the current "EOF on 100-byte probe"
trick relies on the header being readable for key-deferred PRAGMA flow — see
how adiantum/xts handle it with `hbsh == nil` + EOF).

## 7. No test coverage for aux-file path

**Where:** `xchacha_test.go`

**What:** The three existing tests (`Test_roundtrip`, `Test_wrong_key`,
`Test_tamper`) exercise only the main DB file. Missing coverage:

- `PRAGMA journal_mode=WAL` round-trip
- Rollback journal (crash-and-recover, explicit `ROLLBACK`)
- `CREATE TEMP TABLE` (transient DB path)
- Ordering bug from issue 1: WAL opened before `PRAGMA textkey`
- `VACUUM` (exercises subjournal + new-db creation)
- `ATTACH DATABASE` with independent keys

## 8. Minor: URI `key` parameter accepts empty string differently than upstream

**Where:** `api.go:126-131`

**What:** Upstream adiantum's URI parsing:
```go
if t, ok := params["key"]; ok { key = []byte(t[0]) }
```
accepts an empty `key=` as a valid (empty) key — which `HBSH([]byte{})`
then rejects, producing `IOERR_BADKEY`.

xchacha requires `len(t[0]) > 0` for all three params. Behaviorally similar
but divergent. Probably fine; noted for consistency.

## 9. Observability: `setKey` failures are indistinguishable

**Where:** `mainfile.go:33-59` (`setKey`)

**What:** `setKey` returns `sqlite3.IOERR_BADKEY` for three distinct
conditions:
- Key length wrong
- Page size in header doesn't match `pageSize`
- `reserve_bytes` byte in header != 40

All three surface as the same error to the user. A user migrating a DB from
a non-reserve-bytes build would see "bad key" and reasonably conclude the
passphrase is wrong.

**Fix:** Log or return distinct error values. At minimum, return
`sqlite3.IOERR` (or a custom error) for the format-mismatch cases, reserving
`IOERR_BADKEY` for actual key-material problems.
