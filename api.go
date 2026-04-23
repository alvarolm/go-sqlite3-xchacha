// Package xchacha provides an XChaCha20-Poly1305 authenticated-encryption VFS
// for github.com/ncruces/go-sqlite3.
//
// Registering the package installs a VFS named "xchacha":
//
//	import _ "github.com/alvarolm/go-sqlite3-xchacha"
//
// Key material may be supplied via URI parameter or PRAGMA. The recommended
// flow is PRAGMA, which keeps the key out of the connection string:
//
//	db, _ := sql.Open("sqlite3", "file:mydb.db?vfs=xchacha")
//	// For a NEW database, set reserve_bytes before the first write:
//	db.Exec(`PRAGMA reserve_bytes = 40`)
//	db.Exec(`PRAGMA textkey = 'my passphrase'`)
//
// For an existing encrypted database, only the key is needed (reserve_bytes is
// already recorded in the file header):
//
//	db.Exec(`PRAGMA textkey = 'my passphrase'`)
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
//   - Rollback journal / WAL / subjournal: length-preserving XChaCha20 stream
//     cipher with deterministic per-block nonces (HKDF of byte offset).
//     Confidential but NOT authenticated; tampering is caught indirectly when
//     the corrupted data flows back into the main DB on rollback/checkpoint.
package xchacha

import (
	"encoding/hex"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
)

func init() {
	vfs.Register("xchacha", Wrap(vfs.Find(""), nil))
}

// ReserveBytes is an init hook for driver.Open that configures the database
// connection's reserve_bytes to the value this VFS requires (40). It is a
// no-op on existing non-empty databases (per SQLite semantics) and safe to
// pass unconditionally. Use it when creating a new encrypted database:
//
//	db, err := driver.Open("file:new.db?vfs=xchacha", xchacha.ReserveBytes)
//
// Existing encrypted databases don't need this hook; the value is already
// stored in file header byte 20.
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
		if t, ok := params["key"]; ok && len(t[0]) > 0 {
			key = []byte(t[0])
		} else if t, ok := params["hexkey"]; ok && len(t[0]) > 0 {
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
// looked up from the associated main DB via vfsutil.UnwrapFile; if none is
// available (standalone temp/transient file), a random aux key is generated.
func (v *xchachaVFS) openAux(name *vfs.Filename, file vfs.File, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	var auxKey []byte

	if name != nil {
		if main, ok := vfsutil.UnwrapFile[*mainDBFile](name.DatabaseFile()); ok && main.auxKey != nil {
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

	return &auxFile{File: file, auxKey: auxKey}, flags, nil
}
