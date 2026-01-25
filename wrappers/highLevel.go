package wrappers

import "errors"

// Decrypt decrypts the provided byte slice using the provided passphrase.
func Decrypt(encBytes, passphrase []byte) ([]byte, error) {
	if len(encBytes) < saltSize1 {
		return nil, errors.New("High-level decrypt: Encrypted data is too short (invalid Argon2 salt)")
	}
	salt1 := encBytes[:saltSize1]
	encBytes = encBytes[saltSize1:]
	key1 := derivePrimaryKey(passphrase, salt1)
	var err error
	encBytes, err = decryptCha(encBytes, key1)
	if err != nil {
		return nil, err
	}
	encBytes, err = decryptAES(encBytes, key1)
	if err != nil {
		return nil, err
	}
	return encBytes, err
}

// Encrypt encrypts the provided byte slice using the provided passphrase.
func Encrypt(decBytes, passphrase []byte) []byte {
	salt1 := getRandomBytes(saltSize1)
	salt2AES := getRandomBytes(saltSize2)
	salt2Cha := getRandomBytes(saltSize2)
	key1 := derivePrimaryKey(passphrase, salt1)
	key2AES := deriveSecondaryKey(key1, salt2AES, []byte(hkdfInfoAES))
	key2Cha := deriveSecondaryKey(key1, salt2Cha, []byte(hkdfInfoCha))
	decBytes = encryptAES(decBytes, key2AES, salt2AES)
	decBytes = encryptCha(decBytes, key2Cha, salt2Cha)
	// format: salt1 + decBytes per algorithm (salt2* + nonce + ciphertext)
	return append(append(make([]byte, 0, saltSize1+len(decBytes)), salt1...), decBytes...)
}
