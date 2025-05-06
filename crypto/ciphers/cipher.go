package ciphers

import (
	"errors"
	"io"

	"github.com/mxmauro/keyring/crypto/ciphers/aes_gcm"
	"github.com/mxmauro/keyring/models"
)

// -----------------------------------------------------------------------------

type GenerateKeyFunc func(io.Reader) ([]byte, error)
type NewFromKeyFunc func([]byte, io.Reader) (models.Cipher, error)

type engineFunc struct {
	GenerateKey GenerateKeyFunc
	NewFromKey  NewFromKeyFunc
}

// -----------------------------------------------------------------------------

var enginesList = map[string]engineFunc{
	"aes-gcm": {
		GenerateKey: aes_gcm.GenerateKey,
		NewFromKey:  aes_gcm.NewFromKey,
	},
}

var ErrEngineNotSupported = errors.New("engine not supported")

// -----------------------------------------------------------------------------

// SupportedEngines returns a list of supported encryption engines.
func SupportedEngines() []string {
	list := make([]string, 0, len(enginesList))
	for name := range enginesList {
		list = append(list, name)
	}
	return list
}

// IsEngineSupported returns true if the given encryption engine is supported.
func IsEngineSupported(engine string) bool {
	_, ok := enginesList[engine]
	return ok
}

// RegisterEngine registers a custom encryption engine.
func RegisterEngine(engine string, generateKey GenerateKeyFunc, newFromKey NewFromKeyFunc) error {
	if len(engine) == 0 {
		return errors.New("engine name cannot be empty")
	}
	if generateKey == nil || newFromKey == nil {
		return errors.New("generateKey and newFromKey cannot be nil")
	}

	// Check if the engine is already registered
	if _, ok := enginesList[engine]; ok {
		return errors.New("engine already exists")
	}

	// Add the engine to the list.
	enginesList[engine] = engineFunc{
		GenerateKey: generateKey,
		NewFromKey:  newFromKey,
	}

	// Done
	return nil
}

// GenerateKey generates a new key for the given encryption engine.
func GenerateKey(engine string, r io.Reader) ([]byte, error) {
	e, ok := enginesList[engine]
	if !ok {
		return nil, ErrEngineNotSupported
	}
	return e.GenerateKey(r)
}

// NewFromKey creates a new cipher object from the given key and encryption engine.
func NewFromKey(engine string, key []byte, r io.Reader) (models.Cipher, error) {
	e, ok := enginesList[engine]
	if !ok {
		return nil, ErrEngineNotSupported
	}
	return e.NewFromKey(key, r)
}
