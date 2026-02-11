package wrappers

import (
	"errors"

	"github.com/rwinkhart/go-boilerplate/security"
)

// DecryptAndZeroizePassword decrypts the provided byte slice using the provided password.
func DecryptAndZeroizePassword(encBytes, password []byte) ([]byte, error) {
	if len(encBytes) < saltSize1 {
		return nil, errors.New("high-level decrypt: encrypted data is too short (invalid Argon2 salt)")
	}
	salt1 := encBytes[:saltSize1]
	encBytes = encBytes[saltSize1:]
	key1 := derivePrimaryKey(password, salt1)
	security.ZeroizeBytes(password)
	security.ZeroizeBytes(salt1)
	var err error
	encBytes, err = decryptCha(encBytes, key1)
	if err != nil {
		return nil, err
	}
	encBytes, err = decryptAES(encBytes, key1)
	if err != nil {
		return nil, err
	}
	security.ZeroizeBytes(key1)
	return encBytes, err
}

// EncryptAndZeroizeDecBytesAndPassword encrypts the provided byte slice using the provided password.
func EncryptAndZeroizeDecBytesAndPassword(decBytes, password []byte) []byte {
	defer security.ZeroizeBytes(decBytes)
	salt1 := getRandomBytes(saltSize1)
	defer security.ZeroizeBytes(salt1)
	salt2AES := getRandomBytes(saltSize2)
	salt2Cha := getRandomBytes(saltSize2)
	key1 := derivePrimaryKey(password, salt1)
	security.ZeroizeBytes(password)
	key2AES := deriveSecondaryKey(key1, salt2AES, []byte(hkdfInfoAES))
	key2Cha := deriveSecondaryKey(key1, salt2Cha, []byte(hkdfInfoCha))
	security.ZeroizeBytes(key1)
	decBytes = encryptAES(decBytes, key2AES, salt2AES)
	security.ZeroizeBytes(key2AES)
	security.ZeroizeBytes(salt2AES)
	decBytes = encryptCha(decBytes, key2Cha, salt2Cha)
	security.ZeroizeBytes(key2Cha)
	security.ZeroizeBytes(salt2Cha)
	// format: salt1 + decBytes per algorithm (salt2* + nonce + ciphertext)
	return append(append(make([]byte, 0, saltSize1+len(decBytes)), salt1...), decBytes...)
}
