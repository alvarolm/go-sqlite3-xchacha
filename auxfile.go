package xchacha

import (
	"io"

	"golang.org/x/crypto/chacha20"

	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
)

const auxBlockSize = pageSize

func auxRoundDown(i int64) int64 { return i &^ (auxBlockSize - 1) }
func auxRoundUp[T int | int64](i T) T {
	return (i + (auxBlockSize - 1)) &^ (auxBlockSize - 1)
}

// auxFile wraps rollback journal / WAL / subjournal / transient-DB / temp files
// with length-preserving XChaCha20 stream-cipher encryption. Nonce per 4 KiB
// block is derived deterministically from byte offset via HKDF — which leaks
// ciphertext equality at the same offset across snapshots, same as adiantum/xts.
type auxFile struct {
	vfs.File
	auxKey []byte
	block  [auxBlockSize]byte
}

func (f *auxFile) xor(block []byte, blockStart int64) {
	nonce := deriveAuxNonce(f.auxKey, blockStart)
	c, err := chacha20.NewUnauthenticatedCipher(f.auxKey, nonce[:])
	if err != nil {
		panic(err)
	}
	c.XORKeyStream(block, block)
}

func (f *auxFile) ReadAt(p []byte, off int64) (n int, err error) {
	min := auxRoundDown(off)
	max := auxRoundUp(off + int64(len(p)))

	for ; min < max; min += auxBlockSize {
		m, err := f.File.ReadAt(f.block[:], min)
		if m != auxBlockSize {
			return n, err
		}
		f.xor(f.block[:], min)

		data := f.block[:]
		if off > min {
			data = data[off-min:]
		}
		n += copy(p[n:], data)
	}
	return n, nil
}

func (f *auxFile) WriteAt(p []byte, off int64) (n int, err error) {
	min := auxRoundDown(off)
	max := auxRoundUp(off + int64(len(p)))

	for ; min < max; min += auxBlockSize {
		data := f.block[:]
		full := off <= min && len(p[n:]) >= auxBlockSize

		if !full {
			// Partial block: read-decrypt-modify-encrypt-write.
			m, rerr := f.File.ReadAt(f.block[:], min)
			if m == auxBlockSize {
				f.xor(f.block[:], min)
			} else if rerr != io.EOF {
				return n, rerr
			} else {
				// Writing past EOF; zero-pad.
				clear(data)
			}
			if off > min {
				data = data[off-min:]
			}
		}

		t := copy(data, p[n:])
		f.xor(f.block[:], min)

		m, werr := f.File.WriteAt(f.block[:], min)
		if m != auxBlockSize {
			return n, werr
		}
		n += t
	}
	return n, nil
}

func (f *auxFile) Truncate(size int64) error {
	return f.File.Truncate(auxRoundUp(size))
}

func (f *auxFile) SectorSize() int {
	s := f.File.SectorSize()
	if s < auxBlockSize {
		return auxBlockSize
	}
	// LCM-ish: pick the smaller of "base rounded up" or auxBlockSize multiple.
	if s%auxBlockSize == 0 {
		return s
	}
	return auxBlockSize
}

func (f *auxFile) DeviceCharacteristics() vfs.DeviceCharacteristic {
	return f.File.DeviceCharacteristics() & (0 |
		vfs.IOCAP_ATOMIC4K |
		vfs.IOCAP_IMMUTABLE |
		vfs.IOCAP_SEQUENTIAL |
		vfs.IOCAP_SUBPAGE_READ |
		vfs.IOCAP_BATCH_ATOMIC |
		vfs.IOCAP_UNDELETABLE_WHEN_OPEN)
}

func (f *auxFile) ChunkSize(size int)          { vfsutil.WrapChunkSize(f.File, auxRoundUp(size)) }
func (f *auxFile) SizeHint(size int64) error   { return vfsutil.WrapSizeHint(f.File, auxRoundUp(size)) }
func (f *auxFile) Pragma(n, v string) (string, error) { return vfsutil.WrapPragma(f.File, n, v) }
func (f *auxFile) Unwrap() vfs.File             { return f.File }
func (f *auxFile) SharedMemory() vfs.SharedMemory { return vfsutil.WrapSharedMemory(f.File) }
func (f *auxFile) LockState() vfs.LockLevel     { return vfsutil.WrapLockState(f.File) }
func (f *auxFile) PersistentWAL() bool          { return vfsutil.WrapPersistWAL(f.File) }
func (f *auxFile) SetPersistentWAL(keep bool)   { vfsutil.WrapSetPersistWAL(f.File, keep) }
func (f *auxFile) HasMoved() (bool, error)      { return vfsutil.WrapHasMoved(f.File) }
func (f *auxFile) Overwrite() error             { return vfsutil.WrapOverwrite(f.File) }
func (f *auxFile) SyncSuper(s string) error     { return vfsutil.WrapSyncSuper(f.File, s) }
func (f *auxFile) CommitPhaseTwo() error        { return vfsutil.WrapCommitPhaseTwo(f.File) }
func (f *auxFile) BeginAtomicWrite() error      { return vfsutil.WrapBeginAtomicWrite(f.File) }
func (f *auxFile) CommitAtomicWrite() error     { return vfsutil.WrapCommitAtomicWrite(f.File) }
func (f *auxFile) RollbackAtomicWrite() error   { return vfsutil.WrapRollbackAtomicWrite(f.File) }
func (f *auxFile) CheckpointStart()             { vfsutil.WrapCheckpointStart(f.File) }
func (f *auxFile) CheckpointDone()              { vfsutil.WrapCheckpointDone(f.File) }
func (f *auxFile) BusyHandler(h func() bool)    { vfsutil.WrapBusyHandler(f.File, h) }

