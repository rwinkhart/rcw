package daemon

import (
	"crypto/sha256"
	"io"
	"os"

	"github.com/rwinkhart/rcw/wrappers"
)

var Timeout = 300 // seconds for RPC server timeout; configurable

var daemonHash []byte
var globalPassword []byte

// RCWService provides an RPC method.
type RCWService struct{}

// DecryptRequest is the RPC method that decrypts the incoming data using
// the global password and returns the decrypted data
func (h *RCWService) DecryptRequest(encBytes []byte, reply *[]byte) error {
	var err error
	*reply, err = wrappers.DecryptAndZeroizePassword(encBytes, append([]byte{}, globalPassword...)) // pass new slice to avoid zeroizing cached password)
	if err != nil {
		return err
	}
	return nil
}

// EncryptRequestAndZeroizeDecBytes is the RPC method that encrypts the incoming data using
// the global password and returns the encrypted data
func (h *RCWService) EncryptRequestAndZeroizeDecBytes(decBytes []byte, reply *[]byte) error {
	*reply = wrappers.EncryptAndZeroizeDecBytesAndPassword(decBytes, append([]byte{}, globalPassword...)) // pass new slice to avoid zeroizing cached password
	return nil
}

// getFileHash returns the SHA256 hash of the file at the given path.
func getFileHash(path string) []byte {
	file, _ := os.Open(path)
	defer file.Close()
	hash := sha256.New()
	io.Copy(hash, file)
	return hash.Sum(nil)
}
