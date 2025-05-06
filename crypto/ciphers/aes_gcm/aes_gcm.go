package aes_gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/mxmauro/keyring/models"
	"github.com/mxmauro/keyring/util"
)

// -----------------------------------------------------------------------------

const (
	aesKeyLen = 32
)

// -----------------------------------------------------------------------------

type aesGcmCipher struct {
	r    io.Reader
	aead cipher.AEAD

	nonceSize int
	noncePool sync.Pool
}

// -----------------------------------------------------------------------------

// GenerateKey generates a new AES-GCM key.
func GenerateKey(r io.Reader) ([]byte, error) {
	// Generate a 256bit key.
	key := make([]byte, aesKeyLen)

	n, err := r.Read(key)
	if err != nil {
		return nil, err
	}
	if n != aesKeyLen {
		return nil, errors.New("unable to generate aead key")
	}

	// Done.
	return key, nil
}

// NewFromKey creates a new AES-GCM cipher object from the given key.
func NewFromKey(key []byte, r io.Reader) (models.Cipher, error) {
	var aead cipher.AEAD

	if len(key) != aesKeyLen {
		return nil, errors.New("key must be 32 bytes long")
	}

	// Create the AES cipher.
	_cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, util.NewExtendedError(err, "failed to create cipher")
	}

	// Create the GCM in AEAD mode.
	aead, err = cipher.NewGCM(_cipher)
	if err != nil {
		return nil, util.NewExtendedError(err, "failed to create cipher")
	}

	// Create a cipher object.
	c := &aesGcmCipher{
		r:         r,
		aead:      aead,
		nonceSize: aead.NonceSize(),
		noncePool: sync.Pool{},
	}
	c.noncePool.New = func() interface{} {
		return make([]byte, c.nonceSize)
	}

	// Done.
	return c, nil
}

// KeyLen returns the length of the key used by the AES-GCM cipher.
func (c *aesGcmCipher) KeyLen() int {
	return aesKeyLen
}

// Encrypt encrypts the given plaintext using the AES-GCM cipher.
func (c *aesGcmCipher) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate a random nonce.
	nonce := c.noncePool.Get().([]byte)
	n, err := c.r.Read(nonce)
	if err != nil {
		c.noncePool.Put(nonce)
		return nil, err
	}
	if n != c.nonceSize {
		return nil, errors.New("unable to generate aead nonce")
	}

	// Encrypt the plain text.
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	// Build the output.
	output := make([]byte, 2+c.nonceSize+len(ciphertext))
	binary.LittleEndian.PutUint16(output[:2], uint16(uint(c.nonceSize)))
	copy(output[2:2+c.nonceSize], nonce)
	copy(output[2+c.nonceSize:], ciphertext)

	// Done.
	return output, nil
}

// Decrypt decrypts the given ciphertext using the AES-GCM cipher.
func (c *aesGcmCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2 {
		return nil, errors.New("empty or invalid ciphertext")
	}

	// Get the nonce size.
	nonceSize := int(uint(binary.LittleEndian.Uint16(ciphertext[:2])))
	if len(ciphertext) <= 2+nonceSize {
		return nil, errors.New("empty or invalid ciphertext")
	}

	// Get the nonce.
	nonce := ciphertext[2 : 2+nonceSize]

	// Strip the encrypted data.
	ciphertext = ciphertext[2+nonceSize:]

	// Attempt to open (decrypt).
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Done.
	return plaintext, nil
}
