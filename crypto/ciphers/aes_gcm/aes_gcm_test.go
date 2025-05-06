package aes_gcm_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/mxmauro/keyring/crypto/ciphers/aes_gcm"
	"github.com/mxmauro/keyring/models"
)

// -----------------------------------------------------------------------------

var (
	testPlainText = []byte("Hello world!")
)

// -----------------------------------------------------------------------------

func TestAesGcm(t *testing.T) {
	var cipher models.Cipher
	var encryptedData []byte
	var decryptedData []byte

	t.Log("Generating a new key")
	key, err := aes_gcm.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Creating cipher")
	cipher, err = aes_gcm.NewFromKey(key, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Encrypting 'Hello world!'")
	encryptedData, err = cipher.Encrypt(testPlainText)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Decrypting encrypted data")
	decryptedData, err = cipher.Decrypt(encryptedData)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Verifying if decrypted data matches")
	if bytes.Compare(decryptedData, testPlainText) != 0 {
		t.Fatalf("decrypted data does not match test plain text")
	}
}
