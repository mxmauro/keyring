package keyring

import (
	"errors"
)

// -----------------------------------------------------------------------------

var (
	ErrAlreadyInitialized                = errors.New("already initialized")
	ErrNotInitialized                    = errors.New("not initialized")
	ErrAlreadyUnlocked                   = errors.New("already unlocked")
	ErrLocked                            = errors.New("locked")
	ErrNoEncryptionKeysAvailable         = errors.New("no encryption keys available")
	ErrEncryptionKeyNotFound             = errors.New("encryption key not found")
	ErrCannotUnlockIfAutoUnlockIsEnabled = errors.New("cannot unlock if auto-unlock is enabled")
	ErrInvalidStoredData                 = errors.New("invalid stored data")
	ErrNotFound                          = errors.New("not found")
)
