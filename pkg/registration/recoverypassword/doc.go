// Package recoverypassword implements the registration recovery password
// (RRP) subsystem ported from Java Signal-Server's
// org.whispersystems.textsecuregcm.storage.RegistrationRecoveryPasswordsManager.
//
// A recovery password is a client-supplied secret bound to an account's PNI.
// It allows re-registration without an SMS verification session; instead the
// client posts the original password bytes alongside the registration request
// and the server checks them against a previously stored salted hash.
//
// Wire-format parity with Java is mandatory:
//   - hash format is SaltedTokenHash V2: "2." + lower-hex(HKDF-SHA256(token, salt, "authtoken", 32))
//   - token is the lowercase hex encoding of the recovery password byte slice
//   - salt is the lowercase hex encoding of 16 cryptographically random bytes
//
// This package is server-side only; libsignal-rust does not own this format,
// so per the project's layering rules the implementation lives here rather
// than in go-libsignal.
package recoverypassword
