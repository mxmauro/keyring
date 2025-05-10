package keyring_test

import (
	"context"
)

// -----------------------------------------------------------------------------

func autoLockEncrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, len(plaintext))
	for idx, b := range plaintext {
		ciphertext[idx] = b + 1
	}
	return ciphertext, nil
}

func autoLockDecrypt(_ context.Context, ciphertext []byte) ([]byte, error) {
	plaintext := make([]byte, len(ciphertext))
	for idx, b := range ciphertext {
		plaintext[idx] = b - 1
	}
	return plaintext, nil
}
