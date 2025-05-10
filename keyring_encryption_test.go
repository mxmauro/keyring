package keyring_test

import (
	"context"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

func TestEncryption(t *testing.T) {
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

	kr.Destroy()

	// ---------------------------------

	t.Log("Re-creating keyring with the same storage...")
	kr = createKeyring(stg)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Unlocking keyring...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		AutoUnlock: &keyring.AutoUnlockOptions{
			Decrypt: autoLockDecrypt,
		},
	})
	if err != nil {
		t.Fatal("unexpected error:", err)
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
