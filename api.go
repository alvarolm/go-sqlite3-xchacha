// Package xchacha provides an XChaCha20-Poly1305 authenticated-encryption VFS
// for github.com/ncruces/go-sqlite3.
//
// Registering the package installs a VFS named "xchacha":
//
//	import _ "github.com/alvarolm/go-sqlite3-xchacha"
//
// Key material may be supplied via URI parameter or PRAGMA. With
// database/sql connection pools the only correct pattern is a per-connection
// init hook passed to driver.Open — that hook is invoked on EVERY pool
// connection, so both the reserve_bytes FCNTL and the key PRAGMA are
// applied uniformly:
//
//	init := func(c *sqlite3.Conn) error {
//		if err := xchacha.ReserveBytes(c); err != nil { return err }
//		return c.Exec(`PRAGMA textkey = 'my passphrase'`)
//	}
//	db, _ := driver.Open("file:mydb.db?vfs=xchacha", init)
//
// Passing the key through URI parameters (?textkey=/?key=/?hexkey=) does
// reach every pool connection, but it does NOT install reserve_bytes — so
// on a NEW database the first connection writes page 1 with header byte 20
// == 0 and every subsequent pool open fails with NOTADB. URI-based key
// delivery is only safe against a database that was already created with
// the init-hook pattern above.
//
// ATTACH-ed databases are keyed independently — each attached main DB has
// its own key state. The attach URI must carry vfs=xchacha; for an existing
// encrypted file the key must also be supplied in the URI (SQLite reads
// page 1 during ATTACH itself, so the empty-file EOF trick used by the
// primary PRAGMA flow isn't available):
//
//	db.Exec(`ATTACH DATABASE 'file:existing.db?vfs=xchacha&textkey=passphrase' AS other`)
//
// For a brand-new attached database, PRAGMA-after-ATTACH also works (the
// file is empty, so the EOF probe succeeds and ATTACH treats it as a new DB):
//
//	db.Exec(`ATTACH DATABASE 'file:new.db?vfs=xchacha' AS other`)
//	db.Exec(`PRAGMA other.textkey = 'new passphrase'`)
//
// Supported parameters and pragmas:
//
//   - key:     raw 32 bytes
//   - hexkey:  64 hex digits
//   - textkey: passphrase (Argon2id KDF, 64 MiB / t=3 / p=4)
//
// Security summary:
//
//   - Main DB pages: XChaCha20-Poly1305 AEAD, 192-bit random nonce per page,
//     Poly1305 tag, page-number and page-1 header authenticated as AAD.
//     Tamper-evident at the cipher level.
//   - Plaintext header (design choice): bytes 0..100 of page 1 — the SQLite
//     file header — are stored in the clear and bound as AAD rather than
//     encrypted. This leaks file metadata (magic string "SQLite format 3\0",
//     page size, reserve_bytes, file change counter, in-header db size,
//     freelist/schema cookies, text encoding, user_version, application_id,
//     SQLite version number, etc.) to anyone with file access. Tampering is
//     still detected via AAD authentication. This is a deliberate tradeoff:
//     the "pre-key readable header" is what makes the PRAGMA-after-open flow
//     work — on a fresh handle, the 100-byte header probe returns EOF while
//     the file is still empty, so SQLite gives us a chance to receive key
//     material via PRAGMA textkey/key/hexkey before any page is read; once
//     data exists, the header is served directly so SQLite can resolve the
//     page size and reserve_bytes before the key is installed. Upstream
//     adiantum/xts encrypt the header region at the cost of separate
//     key-presence state tracking; this VFS does not. If leaking these
//     metadata fields is unacceptable for your threat model, use upstream
//     adiantum/xts instead.
//   - Rollback journal / WAL / subjournal / transient DB: XChaCha20-Poly1305
//     AEAD per 4096-byte logical block, stored as 4136-byte physical blocks
//     ([ciphertext | nonce | tag]). 192-bit random nonce per write — aux
//     ciphertext is non-deterministic across snapshots and tamper-evident at
//     the cipher level. AAD = role_byte || block_number, so blocks cannot be
//     swapped across roles (WAL ↔ journal). Same-role cross-file block
//     replay is NOT prevented and is out of scope here.
//   - Upgrade note: the aux-file format changed from length-preserving
//     stream cipher to AEAD with physical block widening. Clean shutdown
//     (or manual deletion of *-wal / *-journal files) is required before
//     upgrading. openAux refuses legacy-format aux files with a distinct
//     error rather than surfacing opaque authentication failures.
package xchacha

import (
	"encoding/hex"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
)

func init() {
	vfs.Register("xchacha", Wrap(vfs.Find(""), nil))
}

// ReserveBytes is an init hook for driver.Open that configures the database
// connection's reserve_bytes to the value this VFS requires (40).
//
// Required on EVERY connection when creating a new encrypted database. With
// database/sql pools, that means passing it (plus the key PRAGMA) via the
// driver.Open init hook so the setting is applied to every pool connection,
// not just the first. Skipping it on a create causes page 1 to be written
// with header byte 20 == 0, and mainDBFile.WriteAt will refuse the write
// with IOERR_WRITE rather than silently producing a file that every future
// open rejects with NOTADB.
//
// On existing non-empty databases the call is a no-op (SQLite reads
// reserve_bytes from the file header), so the hook is safe to pass
// unconditionally.
func ReserveBytes(conn *sqlite3.Conn) error {
	_, err := conn.FileControl("main", sqlite3.FCNTL_RESERVE_BYTES, int(reserveBytes))
	return err
}

// Wrap returns a new VFS that encrypts files of the given base VFS.
// If creator is nil, the default XChaCha20-Poly1305 + Argon2id construction is used.
func Wrap(base vfs.VFS, creator Creator) vfs.VFS {
	if creator == nil {
		creator = xchachaCreator{}
	}
	return &xchachaVFS{VFS: base, init: creator}
}

type xchachaVFS struct {
	vfs.VFS
	init Creator
}

func (v *xchachaVFS) Open(name string, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	// The go-sqlite3 VFS interface dispatches through OpenFilename when available;
	// this path is only exercised when name == "" (a transient, unnamed file).
	if name == "" {
		return v.OpenFilename(nil, flags)
	}
	return nil, flags, sqlite3.CANTOPEN
}

func (v *xchachaVFS) OpenFilename(name *vfs.Filename, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	file, flags, err := vfsutil.WrapOpenFilename(v.VFS, name, flags)
	if err != nil {
		return file, flags, err
	}

	// Super journals and pure-memory files are never encrypted.
	if flags&(vfs.OPEN_SUPER_JOURNAL|vfs.OPEN_MEMORY) != 0 {
		return file, flags, nil
	}

	// Dispatch by file role.
	switch {
	case flags&vfs.OPEN_MAIN_DB != 0:
		return v.openMainDB(name, file, flags)
	case flags&vfs.OPEN_TEMP_DB != 0:
		// Temp main-DB (for CREATE TEMP TABLE): same format as main DB, random key.
		mf := &mainDBFile{File: file, init: v.init}
		key := v.init.KDF("")
		if err := mf.setKey(key); err != nil {
			file.Close()
			return nil, flags, err
		}
		return mf, flags, nil
	default:
		// journal / WAL / subjournal / transient DB / temp journal -> aux file.
		return v.openAux(name, file, flags)
	}
}

// openMainDB handles OPEN_MAIN_DB. Key resolution order:
//   - URI parameter key/hexkey/textkey
//   - Deferred to PRAGMA (if none present)
func (v *xchachaVFS) openMainDB(name *vfs.Filename, file vfs.File, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	mf := &mainDBFile{File: file, init: v.init}

	var key []byte
	if name != nil {
		params := name.URIParameters()
		// key / hexkey accept empty values and fall through to setKey, which
		// surfaces IOERR_BADKEY via Keys' length check — matches upstream
		// adiantum. textkey keeps the len>0 guard so an empty textkey= stays
		// PRAGMA-deferred rather than being KDF'd into a random 32-byte key.
		if t, ok := params["key"]; ok {
			key = []byte(t[0])
		} else if t, ok := params["hexkey"]; ok {
			key, _ = hex.DecodeString(t[0])
		} else if t, ok := params["textkey"]; ok && len(t[0]) > 0 {
			key = v.init.KDF(t[0])
		}
	}

	if key != nil {
		if err := mf.setKey(key); err != nil {
			file.Close()
			return nil, flags, err
		}
	}
	return mf, flags, nil
}

// openAux handles journal / WAL / subjournal / transient DB. Key material is
// looked up from the associated main DB via vfsutil.UnwrapFile; if the main
// DB is ours but has not yet received a key, we refuse rather than silently
// writing under an unrecoverable random key. For truly standalone aux files
// (no associated main DB) a random aux key is generated.
//
// Also probes for legacy length-preserving aux files on disk (size multiple
// of 4096 but not 4136) and refuses with a distinct error rather than a
// generic IOERR_DATA on first read.
func (v *xchachaVFS) openAux(name *vfs.Filename, file vfs.File, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	if sz, szErr := file.Size(); szErr == nil && sz > 0 &&
		sz%physBlockSize != 0 && sz%logBlockSize == 0 {
		file.Close()
		return nil, flags, sqlite3.IOERR
	}

	var auxKey []byte
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
		// Standalone aux file (e.g. transient DB with no associated main DB).
		// Give it a random main key and derive the aux subkey from that.
		k := v.init.KDF("")
		_, aux := v.init.Keys(k)
		if aux == nil {
			file.Close()
			return nil, flags, sqlite3.IOERR_BADKEY
		}
		auxKey = aux
	}

	a, err := chacha20poly1305.NewX(auxKey)
	if err != nil {
		file.Close()
		return nil, flags, sqlite3.IOERR_BADKEY
	}
	return &auxFile{File: file, aead: a, role: auxRoleFromFlags(flags)}, flags, nil
}
