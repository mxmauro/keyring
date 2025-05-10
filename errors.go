package keyring

import (
	"errors"
)

// -----------------------------------------------------------------------------

var (
	// ErrAlreadyInitialized should be considered as non-fatal. It is returned in the call to `Initialize`
	// when the keyring is already initialized.
	ErrAlreadyInitialized = errors.New("already initialized")

	// ErrMoreKeysRequired is returned by `Unlock` when the keyring is locked and the user needs to provide
	// more keys to unlock it.
	ErrMoreKeysRequired = errors.New("more keys required")

	// ErrAlreadyUnlocked is returned by `Unlock` when the keyring is already unlocked.
	ErrAlreadyUnlocked = errors.New("already unlocked")

	ErrNotInitialized        = errors.New("not initialized")
	ErrLocked                = errors.New("locked")
	ErrEncryptionKeyNotFound = errors.New("encryption key not found")
	ErrInvalidStoredData     = errors.New("invalid stored data")
	ErrNotFound              = errors.New("not found")
	ErrUnlockFailed          = errors.New("unlock failed")

	ErrKeyringDataHasChanged = errors.New("keyring data has changed")
)
