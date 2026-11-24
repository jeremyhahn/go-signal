// Package recoverypassword stores registration recovery passwords bound to a PNI, as SaltedTokenHash V2: "2." + hex(HKDF-SHA256(hex token, hex 16-byte salt, "authtoken", 32)).
package recoverypassword
