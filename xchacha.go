package xchacha

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"crypto/sha256"
	"io"
)

// pepper domain-separates this VFS's keys from other adapters.
// It is baked into the file format and must not change without a version bump.
//
// Replaceable with:
//
//	go build -ldflags="-X github.com/alvarolm/go-sqlite3-xchacha.pepper=..."
var pepper = "go-sqlite3-xchacha/v1"

const (
	keySize   = chacha20poly1305.KeySize    // 32
	nonceSize = chacha20poly1305.NonceSizeX // 24
	tagSize   = chacha20poly1305.Overhead   // 16

	// reserveBytes is the per-page tail reserved for nonce + Poly1305 tag.
	// The user must set PRAGMA reserve_bytes = 40 before the first write to a new DB.
	reserveBytes = nonceSize + tagSize // 40

	// pageSize is fixed at 4096. SQLite's default and the only value supported here.
	pageSize = 4096

	// usablePerPage is the plaintext region inside each main-DB page.
	usablePerPage = pageSize - reserveBytes // 4056

	// auxHKDFInfoKey domain-separates the aux subkey from the main key.
	auxHKDFInfoKey = "xchacha-aux-v1"

	// auxHKDFInfoNonce domain-separates per-block aux nonces.
	auxHKDFInfoNonce = "xchacha-aux-nonce-v1"
)

// Creator produces an XChaCha20-Poly1305 AEAD and aux key given raw key material.
// A nil AEAD means the key material is not the expected length.
type Creator interface {
	// KDF derives 32 bytes of key material from a passphrase.
	// If text is empty, a random key is returned.
	KDF(text string) []byte

	// Keys constructs the main-DB AEAD and the aux-file subkey.
	// Returns (nil, nil) if key is not 32 bytes.
	Keys(key []byte) (mainAEAD aead, auxKey []byte)
}

// aead is a narrow view of chacha20poly1305.AEAD sufficient for this package.
// Kept as an interface to allow test substitution.
type aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

type xchachaCreator struct{}

func (xchachaCreator) KDF(text string) []byte {
	if text == "" {
		k := make([]byte, keySize)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		return k
	}
	return argon2.IDKey([]byte(text), []byte(pepper), 3, 64*1024, 4, keySize)
}

func (xchachaCreator) Keys(key []byte) (aead, []byte) {
	if len(key) != keySize {
		return nil, nil
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil
	}
	aux := make([]byte, keySize)
	r := hkdf.New(sha256.New, key, nil, []byte(auxHKDFInfoKey))
	if _, err := io.ReadFull(r, aux); err != nil {
		return nil, nil
	}
	return a, aux
}

// deriveAuxNonce produces a deterministic 24-byte XChaCha20 nonce for the
// 4096-byte aux-file block starting at byte offset blockStart.
// Deterministic because aux files are length-preserving — no room to store
// per-block random nonces inline. Domain-separated from the main key via HKDF.
func deriveAuxNonce(auxKey []byte, blockStart int64) (nonce [nonceSize]byte) {
	var salt [8]byte
	// big-endian offset as salt keeps the HKDF expand deterministic and ordered.
	for i := 7; i >= 0; i-- {
		salt[i] = byte(blockStart)
		blockStart >>= 8
	}
	r := hkdf.New(sha256.New, auxKey, salt[:], []byte(auxHKDFInfoNonce))
	if _, err := io.ReadFull(r, nonce[:]); err != nil {
		panic(err)
	}
	return nonce
}
