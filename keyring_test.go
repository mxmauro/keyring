package keyring_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

var (
	plaintextSample = []byte("hello world!!")

	errTestMustFail = errors.New("this sub-test was expected to fail")
)

// -----------------------------------------------------------------------------

func TestKeying(t *testing.T) {
	var firstCiphertext []byte
	var secondCiphertext []byte
	var decPlaintext []byte
	var err error

	ctx := context.Background()

	kr, stg := createKeying(t, true, nil)

	t.Run("Encrypting plaintext without a key (expected to fail)...", func(t *testing.T) {
		firstCiphertext, err = kr.Encrypt(plaintextSample)
		if err == nil {
			t.Fatal(errTestMustFail)
		}
	})

	t.Log("Adding first encryption key...")
	err = kr.AddEncryptionKey(ctx, "aes-gcm")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Encrypting plaintext with first encryption key...")
	firstCiphertext, err = kr.Encrypt(plaintextSample)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Decrypting ciphertext with first encryption key...")
	decPlaintext, err = kr.Decrypt(firstCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintextSample, decPlaintext) {
		t.Fatal("original and decrypted text mismatch")
	}

	t.Log("Adding second encryption key...")
	err = kr.AddEncryptionKey(ctx, "aes-gcm")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Encrypting plaintext with second encryption key...")
	secondCiphertext, err = kr.Encrypt(plaintextSample)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstCiphertext, secondCiphertext) {
		t.Fatal("encryption with second key matches the one with the first key")
	}

	t.Log("Decrypting ciphertext with second encryption key...")
	decPlaintext, err = kr.Decrypt(secondCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintextSample, decPlaintext) {
		t.Fatal("original and decrypted text mismatch")
	}

	t.Log("Destroying keyring instance...")
	kr.Destroy()

	t.Log("Creating keyring with provided storage but no auto-lock (expected to fail)...")
	_, err = keyring.New(context.Background(), keyring.Options{
		BeginStorageTX: stg.BeginTX,
	})
	if err == nil {
		t.Fatal(errTestMustFail)
	}

	kr, stg = createKeying(t, true, stg)

	t.Log("Decrypting ciphertext with first encryption key...")
	decPlaintext, err = kr.Decrypt(firstCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintextSample, decPlaintext) {
		t.Fatal("original and decrypted text mismatch")
	}

	t.Log("Decrypting ciphertext with second encryption key...")
	decPlaintext, err = kr.Decrypt(secondCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintextSample, decPlaintext) {
		t.Fatal("original and decrypted text mismatch")
	}

	t.Log("Destroying keyring instance...")
	kr.Destroy()
}

// -----------------------------------------------------------------------------

func createKeying(t *testing.T, withAutoUnlock bool, stg *TestStorage) (*keyring.Keyring, *TestStorage) {
	var au *TestAutoUnlock

	if stg == nil {
		t.Log("Creating keyring...")
		stg = NewTestStorage()
	} else {
		t.Log("Creating keyring with provided storage...")
	}
	if withAutoUnlock {
		au = NewTestAutoUnlock()
	}

	kr, err := keyring.New(context.Background(), keyring.Options{
		BeginStorageTX:          stg.BeginTX,
		AutoUnlock:              au,
		AutoUnlockRootKeyEngine: "aes-gcm",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Done
	return kr, stg
}
