package xchacha

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
)

// logBlockSize is the plaintext block unit the wrapper presents to SQLite.
// Chosen to match the main-DB page size so aux files (WAL / journal /
// subjournal / transient DB) share an encryption block with a page.
const logBlockSize = pageSize

// physBlockSize is the on-disk block size: logical block + nonce + tag.
// Per-block layout on disk: [ciphertext(logBlockSize) | nonce(nonceSize) | tag(tagSize)].
const physBlockSize = logBlockSize + reserveBytes

func logRoundDown(i int64) int64 { return i &^ (logBlockSize - 1) }
func logRoundUp[T int | int64](i T) T {
	return (i + (logBlockSize - 1)) &^ (logBlockSize - 1)
}
func physRoundUp[T int | int64](i T) T {
	return (logRoundUp(i) / logBlockSize) * physBlockSize
}

func physBlockOff(blockN int64) int64 { return blockN * physBlockSize }

// Aux-file roles. One byte per role is folded into the AEAD AAD alongside the
// block number, so blocks cannot be swapped across roles without failing
// authentication. Cross-file replay within the same role is NOT prevented;
// closing that would require a per-file random salt in a file prologue.
const (
	auxRoleJournal     byte = 0x01 // OPEN_MAIN_JOURNAL
	auxRoleWAL         byte = 0x02 // OPEN_WAL
	auxRoleSubjournal  byte = 0x03 // OPEN_SUBJOURNAL
	auxRoleTempJournal byte = 0x04 // OPEN_TEMP_JOURNAL
	auxRoleTransient   byte = 0x05 // OPEN_TRANSIENT_DB / unknown
)

func auxRoleFromFlags(flags vfs.OpenFlag) byte {
	switch {
	case flags&vfs.OPEN_WAL != 0:
		return auxRoleWAL
	case flags&vfs.OPEN_MAIN_JOURNAL != 0:
		return auxRoleJournal
	case flags&vfs.OPEN_SUBJOURNAL != 0:
		return auxRoleSubjournal
	case flags&vfs.OPEN_TEMP_JOURNAL != 0:
		return auxRoleTempJournal
	default:
		return auxRoleTransient
	}
}

// auxFile wraps rollback journal / WAL / subjournal / transient-DB / temp files
// with per-block XChaCha20-Poly1305 AEAD. Every 4096-byte logical block becomes
// a 4136-byte physical block on disk; offsets are translated at the VFS layer
// and Size() reports the logical size so SQLite still sees block-aligned files.
//
// Fresh random 24-byte nonces are generated per write, so ciphertext is
// non-deterministic across snapshots. AAD = role_byte || blockNumber_be64.
type auxFile struct {
	vfs.File
	aead     aead
	role     byte
	buf      [physBlockSize]byte
	scratch  [logBlockSize]byte // reused plaintext scratch for WriteAt
	aadBuf   [9]byte            // role || blockNumber_be64
	nonceBuf [nonceSize]byte    // nonce scratch — sealBlock generates here, readBlock saves here
}

// aad builds the AAD for a block into f.aadBuf and returns the valid slice.
// Reused across calls; caller must hand it to Seal/Open before the next aad().
func (f *auxFile) aad(blockN int64) []byte {
	f.aadBuf[0] = f.role
	binary.BigEndian.PutUint64(f.aadBuf[1:], uint64(blockN))
	return f.aadBuf[:]
}

// readBlock reads the physical block for blockN, decrypts it, and returns the
// plaintext. Returns io.EOF (or io.ErrUnexpectedEOF) if the block isn't on
// disk, sqlite3.IOERR_DATA on authentication failure, or any other lower-level
// read error unchanged.
//
// Zero-alloc path (modulo x/crypto XChaCha20-Poly1305 internals — subkey AEAD
// and 96-bit nonce per Open, unavoidable from this layer). Decrypts in place
// inside f.buf using the cipher.AEAD documented ciphertext[:0] form: the
// nonce is saved off, the tag is moved down to be contiguous with the
// ciphertext, then Open writes plaintext over the ciphertext region.
func (f *auxFile) readBlock(blockN int64) ([]byte, error) {
	m, rerr := f.File.ReadAt(f.buf[:], physBlockOff(blockN))
	if m != physBlockSize {
		if rerr == nil {
			rerr = io.ErrUnexpectedEOF
		}
		return nil, rerr
	}
	// Save the nonce before the tag move clobbers part of its slot.
	copy(f.nonceBuf[:], f.buf[logBlockSize:logBlockSize+nonceSize])
	// Move the tag down so f.buf[:logBlockSize+tagSize] = ct||tag. Source
	// [logBlockSize+nonceSize : physBlockSize] and destination
	// [logBlockSize : logBlockSize+tagSize] do not overlap (gap at
	// [logBlockSize+tagSize : logBlockSize+nonceSize]); plain copy() is safe.
	copy(f.buf[logBlockSize:logBlockSize+tagSize], f.buf[logBlockSize+nonceSize:physBlockSize])
	ct := f.buf[:logBlockSize+tagSize]
	if _, err := f.aead.Open(ct[:0], f.nonceBuf[:], ct, f.aad(blockN)); err != nil {
		return nil, sqlite3.IOERR_DATA
	}
	return f.buf[:logBlockSize], nil
}

// sealBlock encrypts plain (logBlockSize bytes) with a fresh random nonce and
// writes the resulting physical block to disk at physBlockOff(blockN).
//
// Seals directly into f.buf to avoid the 4 KB ciphertext memcpy. Seal writes
// ct(logBlockSize) || tag(tagSize) starting at f.buf[0]; we then move the tag
// to its on-disk slot at the end and place the nonce in the middle. Ordering
// matters: the tag move must read from [logBlockSize : logBlockSize+tagSize]
// before the nonce write overwrites that range.
func (f *auxFile) sealBlock(blockN int64, plain []byte) error {
	if _, err := rand.Read(f.nonceBuf[:]); err != nil {
		return err
	}
	f.aead.Seal(f.buf[:0], f.nonceBuf[:], plain, f.aad(blockN))
	// f.buf now: [ct(logBlockSize) | tag(tagSize) | stale(nonceSize-tagSize)].
	// Required on-disk: [ct(logBlockSize) | nonce(nonceSize) | tag(tagSize)].
	// Move the tag first (its source range is about to be overwritten by the nonce).
	copy(f.buf[logBlockSize+nonceSize:physBlockSize], f.buf[logBlockSize:logBlockSize+tagSize])
	// Place the nonce into its on-disk slot.
	copy(f.buf[logBlockSize:logBlockSize+nonceSize], f.nonceBuf[:])

	m, werr := f.File.WriteAt(f.buf[:], physBlockOff(blockN))
	if m != physBlockSize {
		return werr
	}
	return nil
}

func (f *auxFile) ReadAt(p []byte, off int64) (n int, err error) {
	min := logRoundDown(off)
	max := logRoundUp(off + int64(len(p)))

	for ; min < max; min += logBlockSize {
		blockN := min / logBlockSize
		plain, rerr := f.readBlock(blockN)
		if rerr != nil {
			if n == 0 && (rerr == io.EOF || rerr == io.ErrUnexpectedEOF) {
				return 0, io.EOF
			}
			return n, rerr
		}
		data := plain
		if off > min {
			data = data[off-min:]
		}
		n += copy(p[n:], data)
	}
	return n, nil
}

func (f *auxFile) WriteAt(p []byte, off int64) (n int, err error) {
	min := logRoundDown(off)
	max := logRoundUp(off + int64(len(p)))

	for ; min < max; min += logBlockSize {
		blockN := min / logBlockSize
		plain := f.scratch[:]
		full := off <= min && len(p[n:]) >= logBlockSize

		if full {
			copy(plain, p[n:n+logBlockSize])
		} else {
			start := int64(0)
			if off > min {
				start = off - min
			}
			writeLen := int64(logBlockSize) - start
			if writeLen > int64(len(p)-n) {
				writeLen = int64(len(p) - n)
			}

			existing, rerr := f.readBlock(blockN)
			switch rerr {
			case nil:
				// readBlock returns f.buf[:logBlockSize]; full overwrite of plain.
				copy(plain, existing)
			case io.EOF, io.ErrUnexpectedEOF:
				// Past EOF: explicitly zero the holes the partial copy won't
				// touch — buffer reuse means we can't rely on implicit zero-init.
				clear(plain[:start])
				clear(plain[start+writeLen:])
			default:
				return n, rerr
			}
			copy(plain[start:], p[n:n+int(writeLen)])
		}

		if err := f.sealBlock(blockN, plain); err != nil {
			return n, err
		}

		if full {
			n += logBlockSize
		} else {
			start := int64(0)
			if off > min {
				start = off - min
			}
			consumed := int64(logBlockSize) - start
			if consumed > int64(len(p)-n) {
				consumed = int64(len(p) - n)
			}
			n += int(consumed)
		}
	}
	return n, nil
}

func (f *auxFile) Truncate(size int64) error {
	return f.File.Truncate(physRoundUp(size))
}

// Size translates the physical on-disk size back to what SQLite expects
// (multiples of logBlockSize). A trailing partial block from an interrupted
// write is floored out — SQLite's WAL recovery trusts mxFrame in the header
// over file size, so trailing garbage is harmless.
func (f *auxFile) Size() (int64, error) {
	phys, err := f.File.Size()
	if err != nil {
		return 0, err
	}
	blocks := phys / physBlockSize
	return blocks * logBlockSize, nil
}

func (f *auxFile) SectorSize() int {
	if s := lcm(f.File.SectorSize(), logBlockSize); s > 0 {
		return s
	}
	return logBlockSize
}

func (f *auxFile) DeviceCharacteristics() vfs.DeviceCharacteristic {
	// Strip IOCAP_ATOMIC4K and IOCAP_BATCH_ATOMIC: physical blocks are 4136 B,
	// so the underlying FS cannot atomically write one block.
	return f.File.DeviceCharacteristics() & (0 |
		vfs.IOCAP_IMMUTABLE |
		vfs.IOCAP_SEQUENTIAL |
		vfs.IOCAP_SUBPAGE_READ |
		vfs.IOCAP_UNDELETABLE_WHEN_OPEN)
}

func (f *auxFile) ChunkSize(size int)                 { vfsutil.WrapChunkSize(f.File, physRoundUp(size)) }
func (f *auxFile) SizeHint(size int64) error          { return vfsutil.WrapSizeHint(f.File, physRoundUp(size)) }
func (f *auxFile) Pragma(n, v string) (string, error) { return vfsutil.WrapPragma(f.File, n, v) }
func (f *auxFile) Unwrap() vfs.File                   { return f.File }
func (f *auxFile) SharedMemory() vfs.SharedMemory     { return vfsutil.WrapSharedMemory(f.File) }
func (f *auxFile) LockState() vfs.LockLevel           { return vfsutil.WrapLockState(f.File) }
func (f *auxFile) PersistWAL() bool                   { return vfsutil.WrapPersistWAL(f.File) }
func (f *auxFile) SetPersistWAL(keep bool)            { vfsutil.WrapSetPersistWAL(f.File, keep) }
func (f *auxFile) HasMoved() (bool, error)            { return vfsutil.WrapHasMoved(f.File) }
func (f *auxFile) Overwrite() error                   { return vfsutil.WrapOverwrite(f.File) }
func (f *auxFile) SyncSuper(s string) error           { return vfsutil.WrapSyncSuper(f.File, s) }
func (f *auxFile) CommitPhaseTwo() error              { return vfsutil.WrapCommitPhaseTwo(f.File) }
func (f *auxFile) BeginAtomicWrite() error            { return vfsutil.WrapBeginAtomicWrite(f.File) }
func (f *auxFile) CommitAtomicWrite() error           { return vfsutil.WrapCommitAtomicWrite(f.File) }
func (f *auxFile) RollbackAtomicWrite() error         { return vfsutil.WrapRollbackAtomicWrite(f.File) }
func (f *auxFile) CheckpointStart()                   { vfsutil.WrapCheckpointStart(f.File) }
func (f *auxFile) CheckpointDone()                    { vfsutil.WrapCheckpointDone(f.File) }
func (f *auxFile) BusyHandler(h func() bool)          { vfsutil.WrapBusyHandler(f.File, h) }
