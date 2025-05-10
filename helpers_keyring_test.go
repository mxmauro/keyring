package keyring_test

import (
	"bytes"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

var (
	plaintextSample = []byte("hello world!!")
)

// -----------------------------------------------------------------------------

func createKeyring(stg *TestStorage) *keyring.Keyring {
	kr, _ := keyring.New(keyring.Options{
		BeginStorageTX: stg.BeginTX,
	})

	// Done
	return kr
}

func encryptPlaintext(t *testing.T, kr *keyring.Keyring, payload []byte) []byte {
	var buf []byte

	if len(payload) == 0 {
		buf = plaintextSample
	} else {
		buf = make([]byte, len(plaintextSample)+len(payload))
		copy(buf, plaintextSample)
		copy(buf[len(plaintextSample):], payload)
	}

	encryptedText, err := kr.Encrypt(buf)
	if err != nil {
		t.Fatal(err)
	}
	return encryptedText
}

func decryptPlaintext(t *testing.T, kr *keyring.Keyring, payload []byte, encryptedText []byte) {
	var buf []byte

	if len(payload) == 0 {
		buf = plaintextSample
	} else {
		buf = make([]byte, len(plaintextSample)+len(payload))
		copy(buf, plaintextSample)
		copy(buf[len(plaintextSample):], payload)
	}

	decryptedText, err := kr.Decrypt(encryptedText)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, decryptedText) {
		t.Fatal("original and decrypted text mismatch")
	}
}
