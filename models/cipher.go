package models

// -----------------------------------------------------------------------------

// Cipher is the minimal interface that must be implemented by all ciphers.
type Cipher interface {
	// KeyLen returns the length of the key used by the cipher.
	KeyLen() int

	// Encrypt encrypts the given plaintext using the cipher.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt decrypts the given ciphertext using the cipher.
	Decrypt(ciphertext []byte) ([]byte, error)
}
