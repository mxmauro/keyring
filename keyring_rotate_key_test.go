package keyring_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

func TestRootKeyRotation(t *testing.T) {
	var originalDecryptionCiphertext []byte
	var newDecryptionCiphertext []byte

	ctx := context.Background()

	t.Log("Creating storage and keyring...")
	stg := newTestStorage()
	kr := createKeyring(stg)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Initializing keyring...")
	_, err := kr.Initialize(ctx, keyring.InitializeOptions{
		Engine: "aes-gcm",
		AutoLock: &keyring.AutoLockOptions{
			Encrypt: autoLockEncrypt,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Encrypting plaintext with initial encryption key...")
	firstEncryptedText := encryptPlaintext(t, kr, []byte("first"))
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Adding a second encryption key...")
	err = kr.AddEncryptionKey(ctx, "aes-gcm")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Encrypting plaintext with second encryption key...")
	secondEncryptedText := encryptPlaintext(t, kr, []byte("second"))
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Locking keyring...")
	kr.Lock()
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Unlocking keyring and saving the original ciphertext for later...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		AutoUnlock: &keyring.AutoUnlockOptions{
			Decrypt: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
				originalDecryptionCiphertext = make([]byte, len(ciphertext))
				copy(originalDecryptionCiphertext, ciphertext)

				return autoLockDecrypt(ctx, ciphertext)
			},
		},
	})
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Rotating root key...")
	_, err = kr.RotateRootKey(ctx, keyring.RotateRootKeyOptions{
		Engine: "aes-gcm",
		AutoLock: &keyring.AutoLockOptions{
			Encrypt: autoLockEncrypt,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("    Success!")

	// ---------------------------------

	kr.Destroy()

	// ---------------------------------

	t.Log("Re-creating keyring with the same storage...")
	kr = createKeyring(stg)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Unlocking keyring and saving the new ciphertext for later...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		AutoUnlock: &keyring.AutoUnlockOptions{
			Decrypt: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
				newDecryptionCiphertext = make([]byte, len(ciphertext))
				copy(newDecryptionCiphertext, ciphertext)

				return autoLockDecrypt(ctx, ciphertext)
			},
		},
	})
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Check if both encryption ciphertexts are different...")
	if bytes.Equal(originalDecryptionCiphertext, newDecryptionCiphertext) {
		t.Fatal("original and new ciphertext are equal")
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Decrypting plaintext with initial encryption key...")
	decryptPlaintext(t, kr, []byte("first"), firstEncryptedText)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Decrypting plaintext with second encryption key...")
	decryptPlaintext(t, kr, []byte("second"), secondEncryptedText)
	t.Log("    Success!")

	// ---------------------------------

	kr.Destroy()
}
