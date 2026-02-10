# RCW (Randall's Cryptographic Wrappers)
RCW is a cascading symmetric cryptography agent meant to be embedded within Go programs.

It encrypts all data with both AES256-GCM and ChaCha20-Poly1305.

Passphrases are securely cached for three minutes and RPC authentication is used to
ensure that only the binary+user responsible for caching the passphrase can utilize it.
This feature is supported on Linux, FreeBSD, MacOS, and Windows. It is disabled if
built with `-tags=interactive`.

RCW also features a sanity check to ensure no data loss occurs due to a user entering the
incorrect passphrase during encryption.

Please note that RCW is a work-in-progress and breaking changes should be expected.
Future versions may not be capable of decrypting the output of the current version.

> [!WARNING]
>It is your responsibility to assess the security and stability of RCW and to ensure it meets your needs before using it.
>I am not responsible for any data loss or breaches of your information resulting from the use of RCW.
>RCW is a new project that is constantly being updated, and though safety and security are priorities, they cannot be guaranteed.

# Usage
For now, please reference [example.go](https://github.com/rwinkhart/randalls-cryptographic-wrappers/blob/main/example.go).

# IMPORTANT - READ FOR FreeBSD+Windows SUPPORT w/RCWD!
There are replacements in the `go.mod` for this module. Make sure you maintain those
same replacements in your importing module, otherwise FreeBSD and Windows support will break
(RCWD support for those operating systems requires patched modules).

# runtime/secret.Do()?
This module does not yet make use of the new `secret.Do()` function in Go 1.26.
The new function is currently in an experimental state and does not function on
non-Linux platforms, thus the current approach to zeroizing in-memory secrets is
a manual one that will work everywhere. If `secret.Do()` becomes more complete in
a future Go version, it will likely be adopted here (on top of the current manual
approach).
