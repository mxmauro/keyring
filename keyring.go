package keyring

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/mxmauro/keyring/crypto/ciphers"
	"github.com/mxmauro/keyring/util"
	"github.com/mxmauro/shamir"
)

// -----------------------------------------------------------------------------

const (
	rootKeyNonceSize = 32
)

// -----------------------------------------------------------------------------

// Keyring implements a secure store and management of encryption keys.
type Keyring struct {
	rg         io.Reader
	beginStgTx BeginStorageTransactionFunc
	autoUnlock AutoUnlock

	mtx sync.RWMutex

	params     keyringParameters
	unlockKeys [][]byte

	rootKey               *keyringKey
	encryptionKeys        keyringKeyMap
	activeEncryptionKeyID uint32
}

// Options configure the Keyring parameters.
type Options struct {
	// A transactional-enabled storage that holds keyring data.
	BeginStorageTX BeginStorageTransactionFunc

	// An optional random number generator reader. If nil, the keyring will use crypto/rand.Reader.
	RandomGeneratorReader io.Reader

	// AutoUnlock, if defined, points to an interface that implements the keyring auto unlock feature.
	AutoUnlock AutoUnlock

	// Encryption engine to use when the auto-unlock feature is enabled and the storage will be initialized.
	AutoUnlockRootKeyEngine string
}

// AutoUnlock defines the keyring auto unlock feature interface.
type AutoUnlock interface {
	// Encrypt function is called when the keyring manager needs to encrypt the root key using the
	// external secure encryption engine like AWS CloudHSM or Azure Dedicated HSM.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)

	// Decrypt function is called when the keyring manager needs to automatically decrypt the root key.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// -----------------------------------------------------------------------------

// New creates a new keyring manager. If the keyring parameters are stored in the storage, it will
// be initialized according.
func New(ctx context.Context, opts Options) (*Keyring, error) {
	var rootKey *keyringKey
	var rootKeyNonce []byte
	var encryptedRootKeyHashToCheck []byte
	var encryptedRootKey []byte
	var decryptedRootKey []byte
	var encryptionKeys keyringKeyMap
	var activeEncryptionKeyID uint32

	rg := opts.RandomGeneratorReader
	if rg == nil {
		rg = rand.Reader
	}

	// Verify if the engine is supported if the auto-unlock feature is used.
	if opts.AutoUnlock != nil && (!ciphers.IsEngineSupported(opts.AutoUnlockRootKeyEngine)) {
		return nil, ciphers.ErrEngineNotSupported
	}

	// Verify if storage is valid.
	if opts.BeginStorageTX == nil {
		return nil, errors.New("invalid storage transaction initiator")
	}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(encryptedRootKey)
		util.SafeZeroMem(decryptedRootKey)
		util.SafeZeroMem(encryptedRootKeyHashToCheck)
		util.SafeZeroMem(rootKeyNonce)
		if rootKey != nil {
			rootKey.Zeroize()
		}
		if encryptionKeys != nil {
			for keyID := range encryptionKeys {
				encryptionKeys[keyID].Zeroize()
			}
		}
	}()

	// Create a new keyring.
	kr := Keyring{
		rg:             rg,
		beginStgTx:     opts.BeginStorageTX,
		autoUnlock:     opts.AutoUnlock,
		encryptionKeys: make(keyringKeyMap),
	}

	// Check if the keyring parameters are stored in the database. Also, check if the root key
	// is stored if the auto-unlock feature is enabled.
	params := keyringParameters{}
	paramsFound := false
	err := kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) (err error) {
		params, err = deserializeKeyringParametersFromStorage(ctx, tx, pathSystemParameters)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				// If system parameters are not stored, keep this keyring uninitialized.
				err = nil
			}
			return
		}
		paramsFound = true

		// Verify stored parameters.
		if kr.autoUnlock == nil {
			if params.shares < 1 || params.threshold < 1 || params.threshold > params.shares {
				err = ErrInvalidStoredData
				return
			}
		} else {
			if params.shares != 0 || params.threshold != 0 {
				err = ErrInvalidStoredData
				return
			}
		}

		// If the auto-unlock feature is enabled, load the encrypted root key.
		if kr.autoUnlock != nil {
			// Load the encrypted root key.
			encryptedRootKey, err = getNonNullValue(ctx, tx, pathSystemRootKey)
			if err != nil {
				return
			}

			// Load the encrypted root key's hash.
			encryptedRootKeyHashToCheck, err = getNonNullValue(ctx, tx, pathSystemRootKeyHash)
			if err != nil {
				return
			}

			// Load the root key nonce.
			rootKeyNonce, err = getNonNullValue(ctx, tx, pathSystemRootKeyNonce)
			if err != nil {
				return
			}
		}

		// Done
		return
	})
	if err != nil {
		return nil, err
	}

	// If parameters were not found, set up a default.
	if !paramsFound {
		params = keyringParameters{}
	}

	// Execute some actions if the auto-unlock feature is enabled.
	if kr.autoUnlock != nil {
		if !paramsFound {
			// The keyring is not initialized, so let's try to (auto) initialize it with the auto-unlock feature.

			// Create a new root key.
			rootKey, err = generateKeyringKey(opts.AutoUnlockRootKeyEngine, kr.rg)
			if err != nil {
				return nil, err
			}

			// Encrypt it with the auto-lock interface.
			encryptedRootKey, err = kr.autoUnlock.Encrypt(ctx, rootKey.Serialize())
			if err != nil {
				return nil, err
			}

			// Create the root key nonce.
			rootKeyNonce, err = kr.generateNonce(rootKeyNonceSize)
			if err != nil {
				return nil, err
			}

			// Create an encrypted hash of the root key using the previously generated nonce.
			encryptedRootKeyHashToCheck, err = rootKey.EncryptedHash(rootKeyNonce)
			if err != nil {
				return nil, err
			}

			// Save into the database.
			err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) (err error) {
				// Check if already initialized (race condition).
				err = isKeyringInitialized(ctx, tx)
				if err != nil {
					return
				}

				// Store the keyring parameters.
				err = params.SerializeToStorage(ctx, tx, pathSystemParameters)
				if err != nil {
					return
				}

				// Store the encrypted root key.
				err = tx.Put(ctx, pathSystemRootKey, encryptedRootKey)
				if err != nil {
					return
				}

				// Store the encrypted root key's hash.
				err = tx.Put(ctx, pathSystemRootKeyHash, encryptedRootKeyHashToCheck)
				if err != nil {
					return
				}

				// Store the root key's nonce.
				err = tx.Put(ctx, pathSystemRootKeyNonce, rootKeyNonce)
				if err != nil {
					return
				}

				// Done
				return
			})
			if err != nil {
				return nil, err
			}
		} else {
			var validationSucceeded bool

			// Parameters are present so, first, decrypt a root key with the external auto-unlock handler.
			decryptedRootKey, err = kr.autoUnlock.Decrypt(ctx, encryptedRootKey)
			if err != nil {
				return nil, err
			}
			rootKey, err = deserializeKeyringKey(decryptedRootKey, kr.rg)
			if err != nil {
				return nil, err
			}

			// Create a hash of the root key plus nonce and encrypt it using the same key.
			validationSucceeded, err = rootKey.ValidateEncryptedHash(encryptedRootKeyHashToCheck, rootKeyNonce)
			if err != nil {
				return nil, err
			}
			if !validationSucceeded {
				return nil, errors.New("the external auto-unlocker returned a wrong key")
			}

			// At this point we have a valid root key!!

			// Read the available encryption keys.
			err = kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) (err error) {
				encryptionKeys, activeEncryptionKeyID, err = kr.readEncryptionKeys(ctx, tx, rootKey)
				return
			})
			if err != nil {
				return nil, err
			}
		}

		// Set up the keys.
		kr.rootKey = rootKey
		rootKey = nil
		if encryptionKeys != nil {
			kr.encryptionKeys = encryptionKeys
			encryptionKeys = nil
		}
		kr.activeEncryptionKeyID = activeEncryptionKeyID
	}

	// We have the parameters.
	kr.params = params

	// Done
	return &kr, nil
}

// Destroy destroys (not physically a keyring). All memory is zeroed.
func (kr *Keyring) Destroy() {
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	//Zero-ize all and lock
	kr.params = keyringParameters{}
	kr.doLock()
}

// Initialize initializes an uninitialized keyring if the auto-unlock feature is not enabled and returns
// the split shamir root key.
func (kr *Keyring) Initialize(ctx context.Context, engine string, shares int, threshold int) (splitRootKey [][]byte, err error) {
	var rootKey *keyringKey
	var rootKeyNonce []byte
	var encryptedRootKeyHash []byte

	// Check if the auto-unlock feature is disabled.
	if kr.autoUnlock != nil {
		return nil, ErrCannotUnlockIfAutoUnlockIsEnabled
	}

	// Check if the engine is supported.
	if !ciphers.IsEngineSupported(engine) {
		return nil, ciphers.ErrEngineNotSupported
	}

	// Verify key split parameters.
	if shares < 1 || shares > 255 || threshold < 1 || threshold > shares {
		return nil, errors.New("invalid shares or threshold parameter")
	}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(encryptedRootKeyHash)
		util.SafeZeroMem(rootKeyNonce)
		if rootKey != nil {
			rootKey.Zeroize()
		}
		if err != nil {
			util.SafeZeroMemArray(splitRootKey)
		}
	}()

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if the keyring is already initialized.
	if kr.params.shares != 0 {
		return nil, ErrAlreadyInitialized
	}

	// Generate a new root key.
	rootKey, err = generateKeyringKey(engine, kr.rg)
	if err != nil {
		return nil, err
	}

	// Split it.
	splitRootKey, err = splitKeyringKey(rootKey, shares, threshold)
	if err != nil {
		return nil, err
	}

	// Create a root key nonce.
	rootKeyNonce, err = kr.generateNonce(rootKeyNonceSize)
	if err != nil {
		return nil, err
	}

	// Create a hash of the root key plus nonce and encrypt it using the same key.
	encryptedRootKeyHash, err = rootKey.EncryptedHash(rootKeyNonce)
	if err != nil {
		return nil, err
	}

	// Save into the database.
	params := keyringParameters{
		shares:    uint8(shares),
		threshold: uint8(threshold),
	}
	err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) (err error) {
		// Check if the storage still contains an uninitialized keyring.
		err = isKeyringInitialized(ctx, tx)
		if err != nil {
			return
		}

		// Store the keyring parameters.
		err = params.SerializeToStorage(ctx, tx, pathSystemParameters)
		if err != nil {
			return
		}

		// Delete the encrypted root key. (It should not exist but....)
		err = tx.Delete(ctx, pathSystemRootKey)
		if err != nil {
			return
		}

		// Store the encrypted root key's hash.
		err = tx.Put(ctx, pathSystemRootKeyHash, encryptedRootKeyHash)
		if err != nil {
			return
		}

		// Store the root key's nonce.
		err = tx.Put(ctx, pathSystemRootKeyNonce, rootKeyNonce)
		if err != nil {
			return
		}

		// Done
		return
	})
	if err != nil {
		return nil, err
	}

	// Store (replace) parameters and mark the keyring as initialized.
	kr.params = params

	// Done.
	return splitRootKey, nil
}

// InitUnlock initiates the unlock procedure.
func (kr *Keyring) InitUnlock() error {
	// Check if the auto-unlock feature is disabled.
	if kr.autoUnlock != nil {
		return ErrCannotUnlockIfAutoUnlockIsEnabled
	}

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if the keyring is initialized.
	if kr.params.shares == 0 {
		return ErrNotInitialized
	}

	// Check if the keyring is already locked.
	if kr.rootKey != nil {
		return ErrAlreadyUnlocked
	}

	// (Re)start the keyring unlock process.
	util.SafeZeroMemArray(kr.unlockKeys)
	kr.unlockKeys = make([][]byte, 0)

	// Done
	return nil
}

// CancelUnlock cancels an active keyring unlock process.
func (kr *Keyring) CancelUnlock() {
	if kr.autoUnlock == nil {
		// Lock access.
		kr.mtx.Lock()
		defer kr.mtx.Unlock()

		//Stop the keyring unlock process.
		util.SafeZeroMemArray(kr.unlockKeys)
		kr.unlockKeys = nil
	}
}

// Unlock tries to unlock the root key.
func (kr *Keyring) Unlock(ctx context.Context, key []byte) (bool, error) {
	var rootKey *keyringKey
	var rootKeyNonce []byte
	var mergedKey []byte
	var encryptedRootKeyHashToCheck []byte
	var encryptionKeys keyringKeyMap
	var activeEncryptionKeyID uint32
	var validationSucceeded bool

	// Check if the auto-unlock feature is disabled.
	if kr.autoUnlock != nil {
		return false, ErrCannotUnlockIfAutoUnlockIsEnabled
	}

	// Validate parameters.
	if len(key) == 0 {
		return false, errors.New("invalid key")
	}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(encryptedRootKeyHashToCheck)
		util.SafeZeroMem(mergedKey)
		util.SafeZeroMem(rootKeyNonce)
		if rootKey != nil {
			rootKey.Zeroize()
		}
		if encryptionKeys != nil {
			for keyID := range encryptionKeys {
				encryptionKeys[keyID].Zeroize()
			}
		}
		util.SafeZeroMemArray(kr.unlockKeys)
	}()

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if the keyring is initialized.
	if kr.unlockKeys == nil {
		return false, errors.New("unlock process has not been initialized")
	}

	// Add the given key to the keyring unlock list.
	kr.unlockKeys = append(kr.unlockKeys, key)

	// Check if we have enough keys.
	if len(kr.unlockKeys) < int(uint(kr.params.threshold)) {
		return false, nil
	}

	// Load the root key parameters from the database.
	err := kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) (err error) {
		// Load the encrypted root key's hash.
		encryptedRootKeyHashToCheck, err = getNonNullValue(ctx, tx, pathSystemRootKeyHash)
		if err != nil {
			return
		}

		// Load the root key nonce.
		rootKeyNonce, err = getNonNullValue(ctx, tx, pathSystemRootKeyNonce)
		if err != nil {
			return
		}

		// Done
		return
	})
	if err != nil {
		return false, err
	}

	// Join keys and recreate the key.
	mergedKey, err = shamir.Combine(kr.unlockKeys)
	if err != nil {
		return false, err
	}
	rootKey, err = deserializeKeyringKey(mergedKey, kr.rg)
	if err != nil {
		return false, err
	}

	// Create a hash of the root key plus nonce and encrypt it using the same key.
	validationSucceeded, err = rootKey.ValidateEncryptedHash(encryptedRootKeyHashToCheck, rootKeyNonce)
	if err != nil {
		return false, err
	}
	if !validationSucceeded {
		return false, errors.New("one or more unlock keys are wrong")
	}

	// At this point we have a valid root key!!

	// Read the available encryption keys.
	err = kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) (err error) {
		encryptionKeys, activeEncryptionKeyID, err = kr.readEncryptionKeys(ctx, tx, rootKey)
		return
	})
	if err != nil {
		return false, err
	}

	// Set up the keys.
	kr.rootKey = rootKey
	rootKey = nil
	kr.encryptionKeys = encryptionKeys
	encryptionKeys = nil
	kr.activeEncryptionKeyID = activeEncryptionKeyID

	// Done
	return true, nil
}

// Lock locks access until unlocked again.
// NOTE: If you lock an auto-unlock keyring, you will need to create a new keyring object based on the same
//
//	storage and auto-unlock interface to unlock it.
func (kr *Keyring) Lock() {
	// Lock access
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Lock keyring if not done yet.
	kr.doLock()
}

func (kr *Keyring) doLock() {
	util.SafeZeroMemArray(kr.unlockKeys)
	kr.unlockKeys = nil

	if kr.rootKey != nil {
		kr.rootKey.Zeroize()
		kr.rootKey = nil
	}

	for idx := range kr.encryptionKeys {
		kr.encryptionKeys[idx].Zeroize()
	}
	kr.encryptionKeys = make(keyringKeyMap)
	kr.activeEncryptionKeyID = 0
}

// IsLocked returns if the keyring is locked or not.
func (kr *Keyring) IsLocked() bool {
	// Lock access
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Return lock status
	return kr.rootKey == nil
}

// RotateRootKey changes the root key. If auto-unlock is disabled, it will return the new split
// shamir set, else splitRootKey will be nil.
func (kr *Keyring) RotateRootKey(ctx context.Context, engine string, shares int, threshold int) (splitRootKey [][]byte, err error) {
	return kr.execRotateRootKey(ctx, engine, shares, threshold)
}

// RotateAutoUnlockRootKey changes the root key. If auto-unlock is disabled, it will return the new split
// shamir set, else splitRootKey will be nil.
func (kr *Keyring) RotateAutoUnlockRootKey(ctx context.Context, engine string) error {
	_, err := kr.execRotateRootKey(ctx, engine, 0, 0)
	return err
}

func (kr *Keyring) execRotateRootKey(ctx context.Context, engine string, shares int, threshold int) (splitRootKey [][]byte, err error) {
	var newRootKey *keyringKey
	var newRootKeyNonce []byte
	var newEncryptedRootKey []byte
	var newEncryptedRootKeyHash []byte

	// Verify key split parameters.
	if kr.autoUnlock == nil {
		if shares < 1 || shares > 255 || threshold < 1 || threshold > shares {
			return nil, errors.New("invalid shares or threshold parameter")
		}
	} else {
		if shares != 0 || threshold != 0 {
			return nil, errors.New("invalid shares or threshold parameter")
		}
	}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(newEncryptedRootKeyHash)
		util.SafeZeroMem(newEncryptedRootKey)
		util.SafeZeroMem(newRootKeyNonce)
		if newRootKey != nil {
			newRootKey.Zeroize()
		}
		if err != nil {
			util.SafeZeroMemArray(splitRootKey)
		}
	}()

	// Lock access
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if we are unlocked.
	if kr.rootKey == nil {
		return nil, ErrLocked
	}

	// Generate a new root key.
	for {
		newRootKey, err = generateKeyringKey(engine, kr.rg)
		if err != nil {
			return nil, err
		}
		if !kr.isDuplicatedKeyID(newRootKey.ID) {
			break
		}
	}

	if kr.autoUnlock == nil {
		// Split it.
		splitRootKey, err = splitKeyringKey(newRootKey, shares, threshold)
		if err != nil {
			return nil, err
		}
	} else {
		// Encrypt it.
		newEncryptedRootKey, err = kr.autoUnlock.Encrypt(ctx, newRootKey.Serialize())
		if err != nil {
			return nil, err
		}
	}

	// Create a root key nonce.
	newRootKeyNonce, err = kr.generateNonce(rootKeyNonceSize)
	if err != nil {
		return nil, err
	}

	// Create a hash of the root key plus nonce and encrypt it using the same key.
	newEncryptedRootKeyHash, err = newRootKey.EncryptedHash(newRootKeyNonce)
	if err != nil {
		return nil, err
	}

	// Save into the database.
	newParams := keyringParameters{
		shares:    uint8(shares),
		threshold: uint8(threshold),
	}
	err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) (err error) {
		err = isKeyringInitialized(ctx, tx)
		if err != nil {
			return
		}

		// Store the new keyring parameters.
		err = tx.Put(ctx, pathSystemParameters, newParams.Serialize())
		if err != nil {
			return
		}

		// Store the new encrypted root key if using the auto-unlock feature.
		if kr.autoUnlock != nil {
			err = tx.Put(ctx, pathSystemRootKey, newEncryptedRootKey)
			if err != nil {
				return
			}
		}

		// Store the new encrypted root key's hash.
		err = tx.Put(ctx, pathSystemRootKeyHash, newEncryptedRootKeyHash)
		if err != nil {
			return
		}

		// Store the new root key's nonce.
		err = tx.Put(ctx, pathSystemRootKeyNonce, newRootKeyNonce)
		if err != nil {
			return
		}

		// Save encryption keys encrypted with the new root key.
		err = kr.writeEncryptionKeys(ctx, tx, newRootKey, kr.encryptionKeys, kr.activeEncryptionKeyID)

		// Done
		return
	})
	if err != nil {
		return nil, err
	}

	// Replace the keyring parameters and current root key.
	kr.params = newParams
	kr.rootKey.Zeroize()
	kr.rootKey = newRootKey
	newRootKey = nil

	// Done
	return splitRootKey, nil
}

// AddEncryptionKey adds a new encryption key to the keyring. Later encryption will use this new key.
func (kr *Keyring) AddEncryptionKey(ctx context.Context, engine string) error {
	var newEncryptionKey *keyringKey
	var err error

	// Zero-ize on exit.
	defer func() {
		if newEncryptionKey != nil {
			newEncryptionKey.Zeroize()
		}
	}()

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if we are unlocked.
	if kr.rootKey == nil {
		return ErrLocked
	}

	// Generate a new encryption key.
	for {
		newEncryptionKey, err = generateKeyringKey(engine, kr.rg)
		if err != nil {
			return err
		}
		if !kr.isDuplicatedKeyID(newEncryptionKey.ID) {
			break
		}
		newEncryptionKey.Zeroize()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Save the new encryption key.
	err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) (err error) {
		err = kr.writeNewEncryptionKey(ctx, tx, newEncryptionKey)
		return
	})
	if err != nil {
		return err
	}

	// Add the new key to the map and set as current.
	kr.encryptionKeys[newEncryptionKey.ID] = newEncryptionKey
	kr.activeEncryptionKeyID = newEncryptionKey.ID
	newEncryptionKey = nil

	// Done
	return nil
}

// Encrypt encrypts the given plain text with the current active encryption key.
func (kr *Keyring) Encrypt(plaintext []byte) ([]byte, error) {
	var ciphertext []byte

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(ciphertext)
	}()

	// Lock access.
	kr.mtx.RLock()
	defer kr.mtx.RUnlock()

	// Check if we are unlocked.
	if kr.rootKey == nil {
		return nil, ErrLocked
	}

	// Get the newest encryption key.
	keysLen := len(kr.encryptionKeys)
	if keysLen == 0 {
		return nil, ErrNoEncryptionKeysAvailable
	}

	// Get the cipher associated with the latest encryption key.
	cipher, err := kr.encryptionKeys[kr.activeEncryptionKeyID].GetCipher()
	if err != nil {
		return nil, err
	}

	// Encrypt data.
	ciphertext, err = cipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	defer util.SafeZeroMem(ciphertext)

	// Build result.
	ret := make([]byte, 1+4+len(ciphertext))
	ret[0] = byte(dataVersion)
	binary.LittleEndian.PutUint32(ret[1:], kr.activeEncryptionKeyID)
	copy(ret[5:], ciphertext)

	// Done
	return ret, nil
}

// Decrypt decrypts the given cipher text with the available encryption keys.
func (kr *Keyring) Decrypt(ciphertext []byte) ([]byte, error) {
	var plaintext []byte

	// Validate input.
	if len(ciphertext) <= 1+idSize {
		return nil, errors.New("ciphertext too short")
	}
	if ciphertext[0] != byte(dataVersion) {
		return nil, errors.New("unsupported ciphertext version")
	}
	encryptionKeyID := binary.LittleEndian.Uint32(ciphertext[1 : 1+idSize])

	// Lock access.
	kr.mtx.RLock()
	defer kr.mtx.RUnlock()

	// Check if we are unlocked.
	if kr.rootKey == nil {
		return nil, ErrLocked
	}

	// Get the encryption key based on the cipher used to encrypt the data.
	encryptionKey, ok := kr.encryptionKeys[encryptionKeyID]
	if !ok {
		return nil, ErrEncryptionKeyNotFound
	}
	cipher, err := encryptionKey.GetCipher()
	if err != nil {
		return nil, err
	}

	// Decrypt data.
	plaintext, err = cipher.Decrypt(ciphertext[1+idSize:])
	if err != nil {
		return nil, err
	}

	// Done
	return plaintext, nil
}

func (kr *Keyring) isDuplicatedKeyID(id uint32) bool {
	if id == kr.rootKey.ID {
		return true
	}
	_, ok := kr.encryptionKeys[id]
	return ok
}

func (kr *Keyring) generateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	l, err := kr.rg.Read(nonce)
	if err != nil || l != size {
		return nil, errors.New("unable to generate nonce")
	}
	return nonce, nil
}

func isKeyringInitialized(ctx context.Context, tx StorageTx) error {
	encodedParams, err := tx.Get(ctx, pathSystemParameters)
	if err != nil {
		return err
	}
	if encodedParams != nil {
		return ErrAlreadyInitialized
	}
	return nil
}

func getNonNullValue(ctx context.Context, tx StorageTx, key string) ([]byte, error) {
	value, err := tx.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, ErrInvalidStoredData
	}
	return value, nil
}

func splitKeyringKey(kk *keyringKey, shares int, threshold int) ([][]byte, error) {
	if shares == 1 {
		split := make([][]byte, 1)
		split[0] = kk.Serialize()
		return split, nil
	}
	// Split the key using the Shamir algorithm.
	return shamir.Split(kk.Serialize(), shares, threshold)
}
