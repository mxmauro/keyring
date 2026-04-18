package ciphers

import (
	"errors"
	"io"
	"sort"
	"sync"

	"github.com/mxmauro/keyring/crypto/ciphers/aes_gcm"
	"github.com/mxmauro/keyring/models"
)

// -----------------------------------------------------------------------------

// GenerateKeyFunc creates a new raw key for a registered cipher engine.
type GenerateKeyFunc func(io.Reader) ([]byte, error)

// NewFromKeyFunc builds a cipher instance from a raw key for a registered engine.
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
var enginesListMtx sync.RWMutex

var ErrEngineNotSupported = errors.New("engine not supported")

// -----------------------------------------------------------------------------

// SupportedEngines returns the names of the currently registered encryption engines.
func SupportedEngines() []string {
	enginesListMtx.RLock()
	defer enginesListMtx.RUnlock()

	list := make([]string, 0, len(enginesList))
	for name := range enginesList {
		list = append(list, name)
	}
	sort.Strings(list)
	return list
}

// IsEngineSupported reports whether engine is registered.
func IsEngineSupported(engine string) bool {
	enginesListMtx.RLock()
	defer enginesListMtx.RUnlock()

	_, ok := enginesList[engine]
	return ok
}

// RegisterEngine adds a custom encryption engine to the registry.
func RegisterEngine(engine string, generateKey GenerateKeyFunc, newFromKey NewFromKeyFunc) error {
	if len(engine) == 0 {
		return errors.New("engine name cannot be empty")
	}
	if generateKey == nil || newFromKey == nil {
		return errors.New("generateKey and newFromKey cannot be nil")
	}

	// Check if the engine is already registered
	enginesListMtx.Lock()
	defer enginesListMtx.Unlock()

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

// GenerateKey creates a new key for engine.
func GenerateKey(engine string, r io.Reader) ([]byte, error) {
	enginesListMtx.RLock()
	e, ok := enginesList[engine]
	enginesListMtx.RUnlock()
	if !ok {
		return nil, ErrEngineNotSupported
	}
	return e.GenerateKey(r)
}

// NewFromKey creates a cipher instance for engine using key.
func NewFromKey(engine string, key []byte, r io.Reader) (models.Cipher, error) {
	enginesListMtx.RLock()
	e, ok := enginesList[engine]
	enginesListMtx.RUnlock()
	if !ok {
		return nil, ErrEngineNotSupported
	}
	return e.NewFromKey(key, r)
}
