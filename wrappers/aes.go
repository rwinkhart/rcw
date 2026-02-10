package wrappers

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/rwinkhart/go-boilerplate/security"
)

const (
	nonceSizeAES = 12 // GCM standard nonce size is 12 bytes
	hkdfInfoAES  = "AES256-GCM"
	hkdfInfoCha  = "ChaCha20-Poly1305"
)

// EncryptAES encrypts data using AES-256-GCM.
func encryptAES(decBytes, key2, salt2 []byte) []byte {
	// create AES-256 cipher
	block, _ := aes.NewCipher(key2)

	// create GCM mode
	aesGCM, _ := cipher.NewGCM(block)

	// generate a random nonce
	nonce := getRandomBytes(nonceSizeAES)
	defer security.ZeroizeBytes(nonce)

	// encrypt the data
	ciphertext := aesGCM.Seal(nil, nonce, decBytes, nil)

	// format: salt2 + nonce + ciphertext
	return append(append(append(make([]byte, 0, saltSize2+nonceSizeAES+len(ciphertext)), salt2...), nonce...), ciphertext...)
}

// DecryptAES decrypts data using AES256-GCM.
func decryptAES(encBytes, key1 []byte) ([]byte, error) {
	if len(encBytes) < saltSize2+nonceSizeAES {
		return nil, errors.New("AES256-GCM: Encrypted data is too short")
	}

	// extract salt, nonce, and ciphertext
	salt2 := encBytes[:saltSize2]
	nonce := encBytes[saltSize2 : saltSize2+nonceSizeAES]
	ciphertext := encBytes[saltSize2+nonceSizeAES:]

	// derive secondary key from primary key using the salt
	key2 := deriveSecondaryKey(key1, salt2, []byte(hkdfInfoAES))

	// create AES-256 cipher
	block, _ := aes.NewCipher(key2)
	security.ZeroizeBytes(key2)

	// create GCM mode
	aesGCM, _ := cipher.NewGCM(block)

	// decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
