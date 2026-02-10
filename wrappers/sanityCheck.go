package wrappers

import (
	"bytes"
	"errors"
	"os"

	"github.com/rwinkhart/go-boilerplate/security"
)

// GenSanityCheckAndZeroizePassphrase creates an encrypted file containing known plaintext
// to later be used for ensuring the user does not encrypt data with
// an incorrect passphrase.
func GenSanityCheckAndZeroizePassphrase(path string, passphrase []byte) error {
	err := os.WriteFile(path, EncryptAndZeroizeDecBytesAndPassphrase([]byte("thx4usin'rcw"), passphrase), 0600)
	security.ZeroizeBytes(passphrase)
	return err
}

// RunSanityCheck should be run before any encryption operation
// to ensure the user does not encrypt data with an incorrect passphrase.
// Failure to perform this check could result in data loss.
func RunSanityCheck(path string, passphrase []byte) error {
	encBytes, err := os.ReadFile(path)
	if err != nil {
		return errors.New("Failed to read sanity check file (" + path + ")")
	}
	decBytes, err := DecryptAndZeroizePassphrase(encBytes, passphrase)
	if err == nil {
		if bytes.Equal(decBytes, []byte("thx4usin'rcw")) {
			return nil
		}
	}
	return errors.New("sanity check failed (likely due to inconsistent passphrase)")
}
