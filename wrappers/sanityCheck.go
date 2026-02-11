package wrappers

import (
	"bytes"
	"errors"
	"os"

	"github.com/rwinkhart/go-boilerplate/security"
)

// GenSanityCheckAndZeroizePassword creates an encrypted file containing known plaintext
// to later be used for ensuring the user does not encrypt data with
// an incorrect password.
func GenSanityCheckAndZeroizePassword(path string, password []byte) error {
	err := os.WriteFile(path, EncryptAndZeroizeDecBytesAndPassword([]byte("thx4usin'rcw"), password), 0600)
	security.ZeroizeBytes(password)
	return err
}

// RunSanityCheck should be run before any encryption operation
// to ensure the user does not encrypt data with an incorrect password.
// Failure to perform this check could result in data loss.
func RunSanityCheck(path string, password []byte) error {
	encBytes, err := os.ReadFile(path)
	if err != nil {
		return errors.New("Failed to read sanity check file (" + path + ")")
	}

	// avoid zeroizing password, as this function expects the user to use the password after running it
	decBytes, err := DecryptAndZeroizePassword(encBytes, append([]byte{}, password...))
	if err == nil {
		if bytes.Equal(decBytes, []byte("thx4usin'rcw")) {
			return nil
		}
	}
	return errors.New("sanity check failed (likely due to inconsistent password)")
}
