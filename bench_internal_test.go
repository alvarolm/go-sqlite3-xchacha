package xchacha

import (
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ncruces/go-sqlite3/vfs"
)

// nopFile is a minimal vfs.File that serves a single in-memory block from
// `backing`. Reads and writes beyond len(backing) are ignored / truncated.
// Good enough to exercise the hot path without touching a real filesystem.
type nopFile struct {
	backing []byte
}

func (n *nopFile) Close() error                                  { return nil }
func (n *nopFile) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(n.backing)) {
		return 0, io.EOF
	}
	return copy(p, n.backing[off:]), nil
}
func (n *nopFile) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	if end > int64(len(n.backing)) {
		grow := make([]byte, end)
		copy(grow, n.backing)
		n.backing = grow
	}
	return copy(n.backing[off:], p), nil
}
func (n *nopFile) Truncate(size int64) error                     { n.backing = n.backing[:size]; return nil }
func (n *nopFile) Sync(vfs.SyncFlag) error                       { return nil }
func (n *nopFile) Size() (int64, error)                          { return int64(len(n.backing)), nil }
func (n *nopFile) Lock(vfs.LockLevel) error                      { return nil }
func (n *nopFile) Unlock(vfs.LockLevel) error                    { return nil }
func (n *nopFile) CheckReservedLock() (bool, error)              { return false, nil }
func (n *nopFile) SectorSize() int                               { return pageSize }
func (n *nopFile) DeviceCharacteristics() vfs.DeviceCharacteristic { return 0 }

// Benchmark_main_db_page_encrypt measures a single WriteAt of one page into
// mainDBFile's encrypted format. Reports allocs/op; the floor is whatever
// x/crypto chacha20poly1305 allocates internally per Seal call.
func Benchmark_main_db_page_encrypt(b *testing.B) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		b.Fatal(err)
	}

	mf := &mainDBFile{File: &nopFile{backing: make([]byte, 0, pageSize*2)}, aead: a}

	page := make([]byte, pageSize)
	if _, err := rand.Read(page); err != nil {
		b.Fatal(err)
	}
	// Valid SQLite-ish header byte 20 so no special paths fire.
	page[20] = reserveBytes

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := mf.WriteAt(page, 0); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark_main_db_page_decrypt measures one decryptPage on a pre-encrypted
// page in f.buf. Reports allocs/op.
func Benchmark_main_db_page_decrypt(b *testing.B) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		b.Fatal(err)
	}

	mf := &mainDBFile{File: &nopFile{backing: make([]byte, 0, pageSize*2)}, aead: a}

	page := make([]byte, pageSize)
	if _, err := rand.Read(page); err != nil {
		b.Fatal(err)
	}
	page[20] = reserveBytes
	if _, err := mf.WriteAt(page, 0); err != nil {
		b.Fatal(err)
	}
	// Now re-read the encrypted page into f.buf, then benchmark decryptPage.
	if _, err := mf.File.ReadAt(mf.buf[:], 0); err != nil {
		b.Fatal(err)
	}
	snapshot := mf.buf

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mf.buf = snapshot // refresh — decryptPage decrypts in place
		if _, err := mf.decryptPage(1); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark_aux_block_seal measures one sealBlock on the auxFile path.
func Benchmark_aux_block_seal(b *testing.B) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		b.Fatal(err)
	}

	af := &auxFile{File: &nopFile{backing: make([]byte, 0, physBlockSize*2)}, aead: a, role: auxRoleWAL}

	plain := make([]byte, logBlockSize)
	if _, err := rand.Read(plain); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := af.sealBlock(0, plain); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark_aux_block_read measures one readBlock on a pre-sealed block.
func Benchmark_aux_block_read(b *testing.B) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		b.Fatal(err)
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		b.Fatal(err)
	}

	af := &auxFile{File: &nopFile{backing: make([]byte, 0, physBlockSize*2)}, aead: a, role: auxRoleWAL}

	plain := make([]byte, logBlockSize)
	if _, err := rand.Read(plain); err != nil {
		b.Fatal(err)
	}
	if err := af.sealBlock(0, plain); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := af.readBlock(0); err != nil {
			b.Fatal(err)
		}
	}
}
