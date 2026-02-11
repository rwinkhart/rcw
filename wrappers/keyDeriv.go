package wrappers

import (
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// parameters for Argon2
	argonTime    = 5           // pass 1-second test on dev environment
	argonMemory  = 1024 * 1024 // 1 GB
	argonThreads = 32          // 32 threads offers the best balance between utilization on high-end devices and performance on low-end devices

	// general constants
	keyLen    = 32 // 256 bits, key length for both algorithms
	saltSize1 = 16 // 128 bits, recommended salt size for AES256/ChaCha20/Argon2
	saltSize2 = 32 // 256 bits, recommended salt size for HKDF
)

// derivePrimaryKey derives an encryption key from a password using Argon2.
// The resulting key is not meant to be used directly for encryption, but rather as a key to derive other keys.
func derivePrimaryKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLen)
}

// deriveSecondaryKey derives a secondary key from the primary key using HKDF.
// It is meant to be an efficient way to derive multiple keys from a single password.
func deriveSecondaryKey(primaryKey, salt, info []byte) []byte {
	h := hkdf.New(sha256.New, primaryKey, salt, info)
	derivedKey := make([]byte, keyLen)
	io.ReadFull(h, derivedKey)
	return derivedKey
}

// getRandomBytes returns a random salt/nonce of the specified size.
func getRandomBytes(size uint8) []byte {
	salt := make([]byte, size)
	io.ReadFull(rand.Reader, salt)
	return salt
}
