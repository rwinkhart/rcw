package wrappers

import (
	"errors"

	"github.com/rwinkhart/go-boilerplate/security"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceSizeCha = chacha20poly1305.NonceSizeX
)

// EncryptCha encrypts data using ChaCha20-Poly1305.
func encryptCha(decBytes, key2, salt2 []byte) []byte {
	// create ChaCha20-Poly1305 cipher
	stream, _ := chacha20poly1305.NewX(key2)

	// generate a random nonce
	nonce := getRandomBytes(nonceSizeCha)

	// encrypt the data
	ciphertext := stream.Seal(nil, nonce, decBytes, nil)

	// format: salt2 + nonce + ciphertext
	return append(append(append(make([]byte, 0, saltSize2+nonceSizeCha+len(ciphertext)), salt2...), nonce...), ciphertext...)
}

// DecryptCha decrypts data using ChaCha20-Poly1305.
func decryptCha(encBytes, key1 []byte) ([]byte, error) {
	if len(encBytes) < saltSize2+nonceSizeCha {
		return nil, errors.New("ChaCha20-Poly1305: Encrypted data is too short")
	}

	// extract salt, nonce, and ciphertext
	salt2 := encBytes[:saltSize2]
	nonce := encBytes[saltSize2 : saltSize2+nonceSizeCha]
	ciphertext := encBytes[saltSize2+nonceSizeCha:]

	// derive secondary key from primary key using the salt
	key2 := deriveSecondaryKey(key1, salt2, []byte(hkdfInfoCha))

	// create ChaCha20-Poly1305 cipher
	stream, _ := chacha20poly1305.NewX(key2)
	security.ZeroizeBytes(key2)

	// decrypt the data
	plaintext, err := stream.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
