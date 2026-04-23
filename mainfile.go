package xchacha

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
)

const (
	headerPlaintext = 100 // first N bytes of page 1 that stay plaintext (the SQLite header)
)

// mainDBFile wraps the OPEN_MAIN_DB (and OPEN_TEMP_DB) file with per-page
// XChaCha20-Poly1305 AEAD. The user must have configured reserve_bytes=40 on
// the database so the last 40 bytes of every page hold the nonce + tag.
//
// If aead is nil, the file is awaiting key material via PRAGMA textkey/key/hexkey.
type mainDBFile struct {
	vfs.File
	init   Creator
	aead   aead   // XChaCha20-Poly1305 on main_key
	auxKey []byte // HKDF(main_key, "xchacha-aux-v1")
	buf    [pageSize]byte
}

// setKey derives and installs the main AEAD + aux subkey. Returns an sqlite3
// error code on failure so callers can propagate straight to SQLite.
func (f *mainDBFile) setKey(key []byte) error {
	a, aux := f.init.Keys(key)
	if a == nil {
		return sqlite3.IOERR_BADKEY
	}
	// Verify reserve_bytes == 40 on existing (non-empty) files.
	size, err := f.File.Size()
	if err != nil {
		return err
	}
	if size > 0 {
		var hdr [headerPlaintext]byte
		if _, rerr := f.File.ReadAt(hdr[:], 0); rerr != nil && rerr != io.EOF {
			return rerr
		}
		// Byte 20 = reserved bytes; bytes 16-17 = page size (1 means 65536).
		if ps := binary.BigEndian.Uint16(hdr[16:18]); ps != pageSize && !(ps == 1 && pageSize == 65536) {
			return sqlite3.IOERR_BADKEY
		}
		if hdr[20] != reserveBytes {
			return sqlite3.IOERR_BADKEY
		}
	}
	f.aead = a
	f.auxKey = aux
	return nil
}

func (f *mainDBFile) Pragma(name, value string) (string, error) {
	var key []byte
	switch name {
	case "key":
		key = []byte(value)
	case "hexkey":
		key, _ = hex.DecodeString(value)
	case "textkey":
		if len(value) > 0 {
			key = f.init.KDF(value)
		}
	default:
		return vfsutil.WrapPragma(f.File, name, value)
	}
	if err := f.setKey(key); err != nil {
		return "", err
	}
	return "ok", nil
}

// ReadAt returns plaintext bytes.
// The underlying file stores: [ciphertext(usablePerPage) | nonce(24) | tag(16)]
// per page, with the exception of page 1 where the first 100 bytes are plaintext
// (the SQLite file header) and the ciphertext region runs from offset 100 to
// usablePerPage.
func (f *mainDBFile) ReadAt(p []byte, off int64) (n int, err error) {
	if f.aead == nil {
		// Adiantum's trick: on a fresh open before PRAGMA textkey/key, the 100-byte
		// header probe returns io.EOF so SQLite treats the file as empty and gives
		// us a chance to receive the key via PRAGMA.
		if off == 0 && len(p) == headerPlaintext {
			return 0, io.EOF
		}
		return 0, sqlite3.CANTOPEN
	}

	// Partial header probe on an encrypted file after the key is set:
	// bytes 0..100 of page 1 are plaintext (AAD) and can be served directly.
	if off == 0 && len(p) <= headerPlaintext {
		return f.File.ReadAt(p, 0)
	}

	min := (off / pageSize) * pageSize
	max := ((off + int64(len(p)) + pageSize - 1) / pageSize) * pageSize

	for page := min; page < max; page += pageSize {
		pageNum := uint64(page/pageSize) + 1

		m, rerr := f.File.ReadAt(f.buf[:], page)
		if m != pageSize {
			if rerr == io.EOF && m == 0 {
				return n, io.EOF
			}
			return n, rerr
		}

		plain, derr := f.decryptPage(pageNum)
		if derr != nil {
			return n, derr
		}

		// Serve the requested slice out of the page.
		start := off - page
		if start < 0 {
			start = 0
		}
		end := int64(pageSize)
		if page+end > off+int64(len(p)) {
			end = off + int64(len(p)) - page
		}
		n += copy(p[n:], plain[start:end])
	}
	return n, nil
}

// decryptPage decrypts f.buf in place and returns the plaintext slice of length
// pageSize. For page 1, the first 100 bytes are passed through as plaintext
// and authenticated as AAD along with the page number.
func (f *mainDBFile) decryptPage(pageNum uint64) ([]byte, error) {
	var pageNumBuf [8]byte
	binary.BigEndian.PutUint64(pageNumBuf[:], pageNum)

	nonce := f.buf[usablePerPage : usablePerPage+nonceSize]
	// ciphertext = f.buf[:usablePerPage] for pages >= 2
	// for page 1, ciphertext = f.buf[headerPlaintext:usablePerPage] with AAD including header.
	tagStart := usablePerPage + nonceSize

	var aad []byte
	var ctStart int
	if pageNum == 1 {
		aad = append(append([]byte(nil), pageNumBuf[:]...), f.buf[:headerPlaintext]...)
		ctStart = headerPlaintext
	} else {
		aad = pageNumBuf[:]
		ctStart = 0
	}

	// Build contiguous ciphertext||tag buffer for Open.
	ciphertext := f.buf[ctStart:usablePerPage]
	tag := f.buf[tagStart:pageSize]
	ctAndTag := make([]byte, 0, len(ciphertext)+tagSize)
	ctAndTag = append(ctAndTag, ciphertext...)
	ctAndTag = append(ctAndTag, tag...)

	plain, err := f.aead.Open(nil, nonce, ctAndTag, aad)
	if err != nil {
		return nil, sqlite3.IOERR_DATA
	}
	copy(f.buf[ctStart:], plain)
	// Zero the reserved tail in the returned plaintext view so SQLite doesn't
	// mistake nonce bytes for data.
	for i := usablePerPage; i < pageSize; i++ {
		f.buf[i] = 0
	}
	return f.buf[:], nil
}

func (f *mainDBFile) WriteAt(p []byte, off int64) (n int, err error) {
	if f.aead == nil {
		return 0, sqlite3.READONLY
	}

	if off%pageSize != 0 || len(p)%pageSize != 0 {
		// Main-DB writes must be whole pages on page boundaries.
		return 0, sqlite3.IOERR_WRITE
	}

	for n < len(p) {
		page := off + int64(n)
		pageNum := uint64(page/pageSize) + 1

		// Copy the plaintext page into our buffer; we own the reserve tail.
		copy(f.buf[:], p[n:n+pageSize])

		var pageNumBuf [8]byte
		binary.BigEndian.PutUint64(pageNumBuf[:], pageNum)

		var aad []byte
		var ptStart int
		if pageNum == 1 {
			aad = append(append([]byte(nil), pageNumBuf[:]...), f.buf[:headerPlaintext]...)
			ptStart = headerPlaintext
		} else {
			aad = pageNumBuf[:]
			ptStart = 0
		}

		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return n, err
		}

		// Seal(plaintext) → ciphertext||tag.
		plaintext := f.buf[ptStart:usablePerPage]
		sealed := f.aead.Seal(nil, nonce, plaintext, aad)
		// sealed = ciphertext (len==plaintext) || tag (16)
		copy(f.buf[ptStart:usablePerPage], sealed[:len(plaintext)])
		copy(f.buf[usablePerPage:usablePerPage+nonceSize], nonce)
		copy(f.buf[usablePerPage+nonceSize:pageSize], sealed[len(plaintext):])

		m, werr := f.File.WriteAt(f.buf[:], page)
		if m != pageSize {
			return n, werr
		}
		n += pageSize
	}
	return n, nil
}

func (f *mainDBFile) Truncate(size int64) error {
	// Round up to page size; main DB truncates happen on page boundaries already.
	if size%pageSize != 0 {
		size = ((size / pageSize) + 1) * pageSize
	}
	return f.File.Truncate(size)
}

func (f *mainDBFile) SectorSize() int {
	s := f.File.SectorSize()
	if s < pageSize {
		return pageSize
	}
	if s%pageSize == 0 {
		return s
	}
	return pageSize
}

func (f *mainDBFile) DeviceCharacteristics() vfs.DeviceCharacteristic {
	return f.File.DeviceCharacteristics() & (0 |
		vfs.IOCAP_ATOMIC4K |
		vfs.IOCAP_IMMUTABLE |
		vfs.IOCAP_SEQUENTIAL |
		vfs.IOCAP_SUBPAGE_READ |
		vfs.IOCAP_BATCH_ATOMIC |
		vfs.IOCAP_UNDELETABLE_WHEN_OPEN)
}

func (f *mainDBFile) ChunkSize(size int)        { vfsutil.WrapChunkSize(f.File, size) }
func (f *mainDBFile) SizeHint(size int64) error { return vfsutil.WrapSizeHint(f.File, size) }
func (f *mainDBFile) Unwrap() vfs.File           { return f.File }
func (f *mainDBFile) SharedMemory() vfs.SharedMemory { return vfsutil.WrapSharedMemory(f.File) }
func (f *mainDBFile) LockState() vfs.LockLevel   { return vfsutil.WrapLockState(f.File) }
func (f *mainDBFile) PersistentWAL() bool        { return vfsutil.WrapPersistWAL(f.File) }
func (f *mainDBFile) SetPersistentWAL(keep bool) { vfsutil.WrapSetPersistWAL(f.File, keep) }
func (f *mainDBFile) HasMoved() (bool, error)    { return vfsutil.WrapHasMoved(f.File) }
func (f *mainDBFile) Overwrite() error           { return vfsutil.WrapOverwrite(f.File) }
func (f *mainDBFile) SyncSuper(s string) error   { return vfsutil.WrapSyncSuper(f.File, s) }
func (f *mainDBFile) CommitPhaseTwo() error      { return vfsutil.WrapCommitPhaseTwo(f.File) }
func (f *mainDBFile) BeginAtomicWrite() error    { return vfsutil.WrapBeginAtomicWrite(f.File) }
func (f *mainDBFile) CommitAtomicWrite() error   { return vfsutil.WrapCommitAtomicWrite(f.File) }
func (f *mainDBFile) RollbackAtomicWrite() error { return vfsutil.WrapRollbackAtomicWrite(f.File) }
func (f *mainDBFile) CheckpointStart()           { vfsutil.WrapCheckpointStart(f.File) }
func (f *mainDBFile) CheckpointDone()            { vfsutil.WrapCheckpointDone(f.File) }
func (f *mainDBFile) BusyHandler(h func() bool)  { vfsutil.WrapBusyHandler(f.File, h) }
