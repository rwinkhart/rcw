package main

import (
	"fmt"
	"os"

	"github.com/rwinkhart/go-boilerplate/front"
	"github.com/rwinkhart/rcw/daemon"
	"github.com/rwinkhart/rcw/wrappers"
)

// This sample program serves purley as a way to interactively test the features
// of RCW before building it into your own application.
//
// Usage:
// rcw init <passwd> : Generates the required sanity check file
// rcw <password> : Runs the rcw daemon to decrypt data for three minutes
// rcw enc <text> : Encrypts the provided text and outputs the ciphertext to ex-cipher.rcw (attempts to use daemon, falls back to user input for password)
// rcw dec : Decrypts ex-cipher.rcw and outputs the plaintext to stdout (attempts to use daemon, falls back to user input for password)

// Implementation Notes:
// There are two main ways to use the RCW library:
//
// 1. Daemon mode:
// The daemon is started with a password and runs in the background.
// All encryption/decryption occurs in the daemon.
// Avoid using the wrapper.Encrypt/Decrypt functions directly.
// Instead, cache the password with the daemon and use the daemon to encrypt/decrypt data.
//
// 2. Standalone mode:
// The wrapper.Encrypt/Decrypt functions are used directly.
// The password is provided directly to the functions.
//
// It is up to the client to perform the sanity check before encrypting data.
// This means that when using the daemon to cache the password, the client should
// perform the sanity check before activating the daemon.

// TODO Tests:
// Salt (aes+chacha)
// Nonce (aes+chacha)
// Encryption (individual+combined)
// Decryption (individual+combined)
// RPC password sharing

// TODO Enhancements:
// Standalone cmd:
//     Usable as symmetric-only GPG replacement

const (
	outputFile = "ex-cipher.rcw"
	sanityFile = "ex-sanity.rcw"
)

func main() {
	switch len(os.Args) {
	case 2:
		if os.Args[1] == "dec" {
			// decrypt file (using daemon if available)
			// rcw dec
			encBytes, err := os.ReadFile(outputFile)
			if err != nil {
				fmt.Println(err)
				return
			}
			var decBytes []byte
			if daemon.IsOpen() {
				decBytes = daemon.GetDec(encBytes)
			} else {
				decBytes, err = wrappers.DecryptAndZeroizePassword(encBytes, front.InputSecret("Enter RCW password:"))
				if err != nil {
					fmt.Println(err)
					return
				}
			}
			fmt.Println(string(decBytes))
			return
		}
		// run decrypter daemon
		// rcw <passwd>
		if daemon.IsOpen() {
			fmt.Println("Daemon already running")
			return
		}
		if err := wrappers.RunSanityCheck(sanityFile, []byte(os.Args[1])); err != nil {
			fmt.Println(err)
			return
		}
		daemon.Start([]byte(os.Args[1]))
	case 3:
		if os.Args[1] == "init" {
			// create sanity check file
			// rcw init <passwd>
			if err := wrappers.GenSanityCheckAndZeroizePassword(sanityFile, []byte(os.Args[2])); err != nil {
				fmt.Println(err)
			}
			return
		} else if os.Args[1] == "enc" {
			// encrypt data (using daemon if available)
			// rcw enc <data>
			decBytes := []byte(os.Args[2])
			var encBytes []byte
			if daemon.IsOpen() {
				encBytes = daemon.GetEncAndZeroizeDecBytes(decBytes)
			} else {
				password := front.InputSecret("Enter RCW password: ")
				if err := wrappers.RunSanityCheck(sanityFile, append([]byte{}, password...)); err != nil { // pass new slice to avoid zeroizing password)
					fmt.Println(err)
					return
				}
				encBytes = wrappers.EncryptAndZeroizeDecBytesAndPassword(decBytes, password)
			}
			os.WriteFile(outputFile, encBytes, 0600)
			return
		}
		fallthrough
	default:
		fmt.Println("Usage: rcw [init <passwd>] | [enc <text>] | dec | <passwd>")
	}
}
