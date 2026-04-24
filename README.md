# go-sqlite3-xchacha

An XChaCha20-Poly1305 authenticated-encryption VFS for [ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3).

> [!CAUTION]
> - not reviewed, use a your own risk, prefer tested implementations, like https://utelle.github.io/SQLite3MultipleCiphers/
> - kdf uses constant salt, use raw keys instead

implementations like these are easier to implements thanks to the work of https://github.com/ncruces


## Install

```sh
go get github.com/alvarolm/go-sqlite3-xchacha
```

## Usage

Importing the package registers a VFS named `xchacha`. With `database/sql` pools, supply the key via a per-connection init hook so both `reserve_bytes` and the key PRAGMA apply to every pooled connection:

```go
import (
    "github.com/ncruces/go-sqlite3"
    "github.com/ncruces/go-sqlite3/driver"
    xchacha "github.com/alvarolm/go-sqlite3-xchacha"
)

init := func(c *sqlite3.Conn) error {
    if err := xchacha.ReserveBytes(c); err != nil {
        return err
    }
    return c.Exec(`PRAGMA textkey = 'my passphrase'`)
}

db, err := driver.Open("file:mydb.db?vfs=xchacha", init)
```

### Key parameters / pragmas

- `key` — raw 32 bytes
- `hexkey` — 64 hex digits
- `textkey` — passphrase (Argon2id KDF, 64 MiB / t=3 / p=4)

URI-based key delivery only works against a database that was already created with the init-hook pattern above; on a brand-new database without `ReserveBytes`, page 1 is written with `reserve_bytes == 0` and every subsequent open fails with `NOTADB`.

## Security

- **Main DB pages:** XChaCha20-Poly1305 AEAD, 192-bit random nonce per page, Poly1305 tag, page number and page-1 header authenticated as AAD.
- **Plaintext header:** bytes 0..100 of page 1 (the SQLite file header) are stored in the clear and bound as AAD. This leaks metadata (magic string, page size, change counter, user_version, etc.) but enables the PRAGMA-after-open flow. If this is unacceptable for your threat model, use upstream `adiantum`/`xts` instead.
- **Journal / WAL / subjournal / transient DB:** XChaCha20-Poly1305 AEAD per 4096-byte logical block, stored as 4136-byte physical blocks. AAD binds role byte and block number so WAL ↔ journal swaps are rejected. Same-role cross-file replay is out of scope.

See the package doc comment in `api.go` for full details.

## Credits

Made using [Claude Code](https://claude.com/claude-code).
