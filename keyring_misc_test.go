package keyring_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

func TestDoubleInit(t *testing.T) {
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

	t.Log("Initializing keyring again...")
	_, err = kr.Initialize(ctx, keyring.InitializeOptions{
		Engine: "aes-gcm",
		AutoLock: &keyring.AutoLockOptions{
			Encrypt: autoLockEncrypt,
		},
	})
	if err == nil {
		t.Fatal("unexpected success")
	}
	if !errors.Is(err, keyring.ErrAlreadyInitialized) {
		t.Fatal("unexpected error:", err)
	}
	t.Log("    Failed as expected!")

	// ---------------------------------

	kr.Destroy()
}
