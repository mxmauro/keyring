package keyring_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

func TestManualLock(t *testing.T) {
	ctx := context.Background()

	t.Log("Creating storage and keyring...")
	stg := newTestStorage()
	kr := createKeyring(stg)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Initializing keyring...")
	initRes, err := kr.Initialize(ctx, keyring.InitializeOptions{
		Engine: "aes-gcm",
		ManualLock: &keyring.ManualLockOptions{
			Threshold: 2,
			Shares:    3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(initRes.ManualLock.SplitRootKey) != 3 {
		t.Fatal("unexpected manual lock return value")
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Encrypting plaintext with initial encryption key...")
	encryptedText := encryptPlaintext(t, kr, nil)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Locking keyring...")
	kr.Lock()
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Trying to unlock a manually locked keyring with auto-unlock...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		AutoUnlock: &keyring.AutoUnlockOptions{
			Decrypt: autoLockDecrypt,
		},
	})
	if err == nil {
		t.Fatal("unexpected success")
	}
	t.Log("    Failed as expected!")

	// ---------------------------------

	t.Log("Unlocking keyring with the third split key...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		ManualUnlock: &keyring.ManualUnlockOptions{
			Key: initRes.ManualLock.SplitRootKey[2],
		},
	})
	if err == nil {
		t.Fatal("unexpected success")
	}
	if !errors.Is(err, keyring.ErrMoreKeysRequired) {
		t.Fatal("unexpected error:", err)
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Unlocking keyring with the first split key...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		ManualUnlock: &keyring.ManualUnlockOptions{
			Key: initRes.ManualLock.SplitRootKey[0],
		},
	})
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Decrypting plaintext with initial encryption key...")
	decryptPlaintext(t, kr, nil, encryptedText)
	t.Log("    Success!")

	// ---------------------------------

	kr.Destroy()
}

func TestAutoLock(t *testing.T) {
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
	encryptedText := encryptPlaintext(t, kr, nil)
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Locking keyring...")
	kr.Lock()
	t.Log("    Success!")

	// ---------------------------------

	t.Log("Trying to unlock an automatically locked keyring with manual-unlock...")
	err = kr.Unlock(ctx, keyring.UnlockOptions{
		ManualUnlock: &keyring.ManualUnlockOptions{
			Key: make([]byte, 16), // A fake key
		},
	})
	if err == nil {
		t.Fatal("unexpected success")
	}
	t.Log("    Failed as expected!")

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
	decryptPlaintext(t, kr, nil, encryptedText)
	t.Log("    Success!")

	// ---------------------------------

	kr.Destroy()
}
