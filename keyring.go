package keyring

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

	mtx sync.RWMutex

	params keyringParameters

	unlockInProgress struct {
		keys   [][]byte
		params keyringParameters
	}

	rootKey               *keyringKey
	encryptionKeys        keyringKeyMap
	activeEncryptionKeyID uint32
}

// Options configure the keyring base options.
type Options struct {
	// A transactional-enabled storage that holds keyring data.
	BeginStorageTX BeginStorageTransactionFunc

	// An optional random number generator reader. If nil, the keyring will use crypto/rand.Reader.
	RandomGeneratorReader io.Reader
}

// InitializeOptions is a set of options to use to initialize the keyring.
type InitializeOptions struct {
	// Encryption engine to use for the initial encryption key.
	Engine string

	// Encryption engine to use for the root key. If not defined, the same engine for encryption keys will be used.
	RootKeyEngine string

	ManualLock *ManualLockOptions
	AutoLock   *AutoLockOptions
}

// ManualLockOptions defines the keyring manual-lock feature options.
type ManualLockOptions struct {
	// Threshold defines the minimum number of keys required to unlock the keyring.
	Threshold int

	// Shares is the number of splits the root key will have.
	Shares int
}

// AutoLockOptions defines the keyring auto-lock feature options.
type AutoLockOptions struct {
	// Encrypt function to call when the keyring manager needs to encrypt the root key using the
	// external secure encryption engine like AWS CloudHSM or Azure Dedicated HSM.
	Encrypt func(ctx context.Context, plaintext []byte) ([]byte, error)
}

// InitializeResult is returned as a result of the keyring initialization process.
type InitializeResult struct {
	ManualLock ManualLockResult
}

// ManualLockResult contains the result of a manual-lock keyring.
type ManualLockResult struct {
	// SplitRootKey will hold the split shamir root key.
	SplitRootKey [][]byte
}

// UnlockOptions is a set of options used to unlock the keyring.
type UnlockOptions struct {
	ManualUnlock *ManualUnlockOptions
	AutoUnlock   *AutoUnlockOptions
}

// ManualUnlockOptions establishes the options to use when manual-locking is used.
type ManualUnlockOptions struct {
	// One of the split keys to unlock the keyring.
	Key []byte
}

// AutoUnlockOptions establishes the options to use when the auto-locking feature is used.
type AutoUnlockOptions struct {
	// Function to call when the keyring manager needs to decrypt the root key.
	Decrypt func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// RotateRootKeyOptions is a set of options to use to rotate the root key of the keyring.
type RotateRootKeyOptions struct {
	// Encryption engine to use for the root key.
	Engine string

	ManualLock *ManualLockOptions
	AutoLock   *AutoLockOptions
}

// RotateRootKeyResult is returned as a result of the root key rotation process.
type RotateRootKeyResult struct {
	ManualLock ManualLockResult
}

// -----------------------------------------------------------------------------

// New creates a new keyring manager.
func New(opts Options) (*Keyring, error) {
	rg := opts.RandomGeneratorReader
	if rg == nil {
		rg = rand.Reader
	}

	// Verify if storage is valid.
	if opts.BeginStorageTX == nil {
		return nil, errors.New("invalid storage transaction initiator")
	}

	// Create a new keyring.
	kr := Keyring{
		rg:             rg,
		beginStgTx:     opts.BeginStorageTX,
		encryptionKeys: make(keyringKeyMap),
	}

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

// Status returns the current status of the keyring. It can be used to check if the keyring is initialized, unlocked
// or if another instance using the same database changed any keyring configuration.
//
// ErrLocked is returned if the keyring is locked.
//
// ErrKeyringDataHasChanged is returned if an encryption key was added or the root key or a parameter was changed.
func (kr *Keyring) Status(ctx context.Context) error {
	kr.mtx.RLock()
	defer kr.mtx.RUnlock()

	// Check if the keyring is already unlocked.
	if !kr.isUnlocked() {
		return ErrLocked
	}

	// Check in the database if there was any change.
	err := kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) (err2 error) {
		err2 = isStorageInitialized(ctx, tx, &kr.params.uniqueID, &kr.params.revision)
		return
	})

	// Done
	return err
}

// Initialize initializes an uninitialized keyring.
// NOTE: If initialization succeeds, the keyring remains unlocked.
func (kr *Keyring) Initialize(ctx context.Context, opts InitializeOptions) (InitializeResult, error) {
	var rootKey *keyringKey
	var encryptedRootKey []byte
	var rootKeyNonce []byte
	var encryptedRootKeyHash []byte
	var encryptionKeys keyringKeyMap
	var activeEncryptionKeyID uint32
	var err error

	// Check if the engine is supported.
	if !ciphers.IsEngineSupported(opts.Engine) {
		return InitializeResult{}, ciphers.ErrEngineNotSupported
	}
	if len(opts.RootKeyEngine) > 0 {
		if !ciphers.IsEngineSupported(opts.RootKeyEngine) {
			return InitializeResult{}, ciphers.ErrEngineNotSupported
		}
	} else {
		opts.RootKeyEngine = opts.Engine
	}

	// Check lock options.
	if opts.ManualLock != nil {
		if opts.AutoLock != nil {
			return InitializeResult{}, errors.New("use either ManualLock or AutoLock, not both")
		}

		// Verify key split parameters.
		if opts.ManualLock.Shares < 1 || opts.ManualLock.Shares > 255 {
			return InitializeResult{}, errors.New("invalid shares parameter")
		}
		if opts.ManualLock.Threshold < 1 || opts.ManualLock.Threshold > opts.ManualLock.Shares {
			return InitializeResult{}, errors.New("invalid threshold parameter")
		}
	} else if opts.AutoLock != nil {
		// Verify if the encrypt function is specified.
		if opts.AutoLock.Encrypt == nil {
			return InitializeResult{}, errors.New("auto-lock encrypt function is nil")
		}
	} else {
		return InitializeResult{}, errors.New("neither ManualLock nor AutoLock was specified")
	}

	// Initialize result data.
	ret := InitializeResult{}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(encryptedRootKey)
		util.SafeZeroMem(encryptedRootKeyHash)
		util.SafeZeroMem(rootKeyNonce)
		if rootKey != nil {
			rootKey.Zeroize()
		}
		if encryptionKeys != nil {
			for keyID := range encryptionKeys {
				encryptionKeys[keyID].Zeroize()
			}
		}
		if err != nil {
			util.SafeZeroMemArray(ret.ManualLock.SplitRootKey)
		}
	}()

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Quick check if the keyring is already initialized.
	if kr.isUnlocked() {
		return InitializeResult{}, ErrAlreadyInitialized
	}

	// Generate a new root key.
	rootKey, err = generateKeyringKey(opts.RootKeyEngine, kr.rg)
	if err != nil {
		return InitializeResult{}, err
	}

	// Split or encrypt the root key.
	if opts.ManualLock != nil {
		// Split it.
		ret.ManualLock.SplitRootKey, err = rootKey.Split(opts.ManualLock.Shares, opts.ManualLock.Threshold)
		if err != nil {
			return InitializeResult{}, err
		}
	} else {
		// Encrypt it.
		encryptedRootKey, err = opts.AutoLock.Encrypt(ctx, rootKey.Serialize())
		if err != nil {
			return InitializeResult{}, err
		}
	}

	// Create a root key nonce.
	rootKeyNonce, err = kr.generateNonce(rootKeyNonceSize)
	if err != nil {
		return InitializeResult{}, err
	}

	// Create a hash of the root key plus nonce and encrypt it using the same key.
	encryptedRootKeyHash, err = rootKey.EncryptedHash(rootKeyNonce)
	if err != nil {
		return InitializeResult{}, err
	}

	// Generate a new encryption key.
	encryptionKeys = make(keyringKeyMap)
	activeEncryptionKeyID, err = encryptionKeys.generateAndAddNewEncryptionKey(ctx, opts.Engine, kr.rg, rootKey.ID)
	if err != nil {
		return InitializeResult{}, err
	}

	// Set up the keyring parameters.
	params := keyringParameters{}
	params.uniqueID, err = kr.generateRandomUint64()
	if err != nil {
		return InitializeResult{}, err
	}
	params.revision = 1
	if opts.ManualLock != nil {
		params.shares = uint8(opts.ManualLock.Shares)
		params.threshold = uint8(opts.ManualLock.Threshold)
	} else {
		params.usingAutoUnlock = true
	}

	// Save into the database.
	err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) error {
		// Check if the storage still contains an uninitialized keyring.
		err2 := isStorageInitialized(ctx, tx, nil, nil)
		if err2 == nil {
			return ErrAlreadyInitialized
		}
		if !errors.Is(err2, ErrNotFound) {
			return err2
		}

		// Store the keyring parameters.
		err2 = params.SerializeToStorage(ctx, tx, pathKeyringParameters)
		if err2 != nil {
			return err2
		}

		if opts.ManualLock != nil {
			// Delete the encrypted root key. (It should not exist but....)
			err2 = tx.Delete(ctx, pathKeyringRootKey)
		} else {
			// Store the encrypted root key.
			err2 = tx.Put(ctx, pathKeyringRootKey, encryptedRootKey)
		}
		if err2 != nil {
			return err2
		}

		// Store the encrypted root key's hash.
		err2 = tx.Put(ctx, pathKeyringRootKeyHash, encryptedRootKeyHash)
		if err2 != nil {
			return err2
		}

		// Store the root key's nonce.
		err2 = tx.Put(ctx, pathKeyringRootKeyNonce, rootKeyNonce)
		if err2 != nil {
			return err2
		}

		// Save the new encryption key.
		err2 = kr.writeEncryptionKeys(ctx, tx, rootKey, encryptionKeys, activeEncryptionKeyID)

		// Done
		return err2
	})
	if err != nil {
		return InitializeResult{}, err
	}

	// Store the keyring parameters and mark the keyring as initialized.
	kr.params = params

	// Set up the root key.
	kr.rootKey = rootKey
	rootKey = nil

	// Set up the encryption keys.
	kr.encryptionKeys = encryptionKeys
	encryptionKeys = nil
	kr.activeEncryptionKeyID = activeEncryptionKeyID

	// Done
	return ret, nil
}

// Unlock tries to unlock the root key.
func (kr *Keyring) Unlock(ctx context.Context, opts UnlockOptions) error {
	var rootKey *keyringKey
	var rootKeyNonce []byte
	var mergedKey []byte
	var encryptedRootKeyHashToCheck []byte
	var encryptedRootKey []byte
	var decryptedRootKey []byte
	var encryptedEncryptionKeys [][]byte
	var encryptionKeys keyringKeyMap
	var activeEncryptionKeyID uint32
	var validationSucceeded bool
	var err error

	// Check unlock options.
	if opts.ManualUnlock != nil {
		if opts.AutoUnlock != nil {
			return errors.New("use either ManualUnlock or AutoUnlock, not both")
		}

		// Verify key parameter.
		if len(opts.ManualUnlock.Key) == 0 {
			return errors.New("invalid key parameter")
		}
	} else if opts.AutoUnlock != nil {
		// Verify if the encrypt function is specified.
		if opts.AutoUnlock.Decrypt == nil {
			return errors.New("auto-unlock decrypt function is nil")
		}
	} else {
		return errors.New("neither ManualUnlock nor AutoUnlock was specified")
	}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(encryptedRootKey)
		util.SafeZeroMem(decryptedRootKey)
		util.SafeZeroMem(encryptedRootKeyHashToCheck)
		util.SafeZeroMemArray(encryptedEncryptionKeys)
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
	}()

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Except we need more keys, cancel the unlocking process on exit.
	resetUnlockInProgress := true
	defer func() {
		if resetUnlockInProgress {
			kr.doCancelUnlock()
		}
	}()

	// Check if the keyring is already unlocked.
	if kr.isUnlocked() {
		return ErrAlreadyUnlocked
	}

	// Set up unlock in-progress details.
	if kr.unlockInProgress.keys == nil {
		err = kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) (err2 error) {
			kr.unlockInProgress.params, err2 = deserializeKeyringParametersFromStorage(ctx, tx, pathKeyringParameters)
			return
		})
		if err != nil {
			// If the keyring parameters are not found, it means that the keyring is not initialized.
			if errors.Is(err, ErrNotFound) {
				return ErrNotInitialized
			}
			return err
		}

		// Initialize the key array.
		kr.unlockInProgress.keys = make([][]byte, 0)
	}

	// Check if the proper unlock method is used.
	if !kr.unlockInProgress.params.usingAutoUnlock {
		if opts.ManualUnlock == nil {
			return errors.New("this keyring uses manual locking")
		}
	} else {
		if opts.AutoUnlock == nil {
			return errors.New("this keyring uses auto locking")
		}
	}

	// If using manual unlock, check if the unlocking procedure was already started.
	if !kr.unlockInProgress.params.usingAutoUnlock {
		// Add the given key to the keyring unlock list.
		kr.unlockInProgress.keys = append(kr.unlockInProgress.keys, opts.ManualUnlock.Key)

		// Check if we have enough keys.
		if len(kr.unlockInProgress.keys) < int(uint(kr.unlockInProgress.params.threshold)) {
			resetUnlockInProgress = false
			return ErrMoreKeysRequired
		}

		// Combine the keys.
		mergedKey, err = shamir.Combine(kr.unlockInProgress.keys)
		if err != nil {
			return err
		}
	}

	// Load the root key, parameters and other things from the database.
	err = kr.withinTx(ctx, true, func(ctx context.Context, tx StorageTx) error {
		// Check if the storage still contains the same parameters.
		err2 := isStorageInitialized(ctx, tx, &kr.unlockInProgress.params.uniqueID, &kr.unlockInProgress.params.revision)
		if err2 != nil {
			return err2
		}

		// Load the encrypted root key if executing the auto-unlock process.
		if opts.AutoUnlock != nil {
			encryptedRootKey, err2 = getNonNullValue(ctx, tx, pathKeyringRootKey)
			if err2 != nil {
				return err2
			}
		}

		// Load the encrypted root key's hash.
		encryptedRootKeyHashToCheck, err2 = getNonNullValue(ctx, tx, pathKeyringRootKeyHash)
		if err2 != nil {
			return err2
		}

		// Load the root key nonce.
		rootKeyNonce, err2 = getNonNullValue(ctx, tx, pathKeyringRootKeyNonce)
		if err2 != nil {
			return err2
		}

		// Load the stored encryption keys.
		encryptedEncryptionKeys, activeEncryptionKeyID, err2 = kr.readEncryptionKeys(ctx, tx)

		// Done
		return err2
	})
	if err != nil {
		return err
	}

	// Recreate the root key.
	if !kr.unlockInProgress.params.usingAutoUnlock {
		rootKey, err = deserializeKeyringKey(mergedKey, kr.rg)
		if err != nil {
			return err
		}
	} else {
		decryptedRootKey, err = opts.AutoUnlock.Decrypt(ctx, encryptedRootKey)
		if err != nil {
			return err
		}
		rootKey, err = deserializeKeyringKey(decryptedRootKey, kr.rg)
		if err != nil {
			return err
		}
	}

	// Validate the root key by creating a hash of the root key plus nonce and encrypt it using the same key.
	validationSucceeded, err = rootKey.ValidateEncryptedHash(encryptedRootKeyHashToCheck, rootKeyNonce)
	if err != nil {
		return err
	}
	if !validationSucceeded {
		return ErrUnlockFailed
	}

	// At this point we have a valid root key!!

	// Decrypt the encryption keys and validate the active one.
	encryptionKeys, err = kr.decryptEncryptionKeys(encryptedEncryptionKeys, rootKey)
	if err != nil {
		return err
	}
	if _, ok := encryptionKeys[activeEncryptionKeyID]; !ok {
		return fmt.Errorf("active encription key with ID 0x%X not found", activeEncryptionKeyID)
	}

	// Store parameters and mark the keyring as initialized.
	kr.params = kr.unlockInProgress.params

	// Set up the root key.
	kr.rootKey = rootKey
	rootKey = nil

	// Add the first encryption key to the map and set as current.
	kr.encryptionKeys = encryptionKeys
	kr.activeEncryptionKeyID = activeEncryptionKeyID
	encryptionKeys = nil

	// Done
	return nil
}

// CancelUnlock cancels an active keyring unlock process.
func (kr *Keyring) CancelUnlock() {
	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	//Stop the keyring unlock process.
	kr.doCancelUnlock()
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
	kr.unlockInProgress.params = keyringParameters{}
	util.SafeZeroMemArray(kr.unlockInProgress.keys)
	kr.unlockInProgress.keys = nil

	if kr.rootKey != nil {
		kr.rootKey.Zeroize()
		kr.rootKey = nil
	}

	for keyID := range kr.encryptionKeys {
		kr.encryptionKeys[keyID].Zeroize()
	}
	kr.encryptionKeys = make(keyringKeyMap)
	kr.activeEncryptionKeyID = 0

	kr.params = keyringParameters{}
}

func (kr *Keyring) doCancelUnlock() {
	kr.unlockInProgress.params = keyringParameters{}
	util.SafeZeroMemArray(kr.unlockInProgress.keys)
	kr.unlockInProgress.keys = nil
}

// IsLocked returns if the keyring is locked or not.
func (kr *Keyring) IsLocked() bool {
	// Lock access.
	kr.mtx.RLock()
	defer kr.mtx.RUnlock()

	// Return lock state.
	return !kr.isUnlocked()
}

// RotateRootKey changes the root key. It also allows to change from manual to auto-locking and vice versa.
func (kr *Keyring) RotateRootKey(ctx context.Context, opts RotateRootKeyOptions) (RotateRootKeyResult, error) {
	var newRootKey *keyringKey
	var newRootKeyNonce []byte
	var newEncryptedRootKey []byte
	var newEncryptedRootKeyHash []byte
	var err error

	// Check if the engine is supported.
	if !ciphers.IsEngineSupported(opts.Engine) {
		return RotateRootKeyResult{}, ciphers.ErrEngineNotSupported
	}

	// Check lock options.
	if opts.ManualLock != nil {
		if opts.AutoLock != nil {
			return RotateRootKeyResult{}, errors.New("use either ManualLock or AutoLock, not both")
		}

		// Verify key split parameters.
		if opts.ManualLock.Shares < 1 || opts.ManualLock.Shares > 255 || opts.ManualLock.Threshold < 1 || opts.ManualLock.Threshold > opts.ManualLock.Shares {
			return RotateRootKeyResult{}, errors.New("invalid shares or threshold parameter")
		}
	} else if opts.AutoLock != nil {
		// Verify if the encrypt function is specified.
		if opts.AutoLock.Encrypt == nil {
			return RotateRootKeyResult{}, errors.New("auto-lock encrypt function is nil")
		}
	} else {
		return RotateRootKeyResult{}, errors.New("invalid options")
	}

	// Initialize result data.
	ret := RotateRootKeyResult{}

	// Zero-ize on exit.
	defer func() {
		util.SafeZeroMem(newEncryptedRootKeyHash)
		util.SafeZeroMem(newEncryptedRootKey)
		util.SafeZeroMem(newRootKeyNonce)
		if newRootKey != nil {
			newRootKey.Zeroize()
		}
		if err != nil {
			util.SafeZeroMemArray(ret.ManualLock.SplitRootKey)
		}
	}()

	// Lock access
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if the keyring is already unlocked.
	if !kr.isUnlocked() {
		return RotateRootKeyResult{}, ErrLocked
	}

	// Generate a new root key.
	for {
		newRootKey, err = generateKeyringKey(opts.Engine, kr.rg)
		if err != nil {
			return RotateRootKeyResult{}, err
		}

		if !kr.encryptionKeys.containsID(newRootKey.ID) {
			break
		}

		newRootKey.Zeroize()

		select {
		case <-ctx.Done():
			return RotateRootKeyResult{}, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Split or encrypt the new root key.
	if opts.ManualLock != nil {
		// Split it.
		ret.ManualLock.SplitRootKey, err = newRootKey.Split(opts.ManualLock.Shares, opts.ManualLock.Threshold)
		if err != nil {
			return RotateRootKeyResult{}, err
		}
	} else {
		// Encrypt it.
		newEncryptedRootKey, err = opts.AutoLock.Encrypt(ctx, newRootKey.Serialize())
		if err != nil {
			return RotateRootKeyResult{}, err
		}
	}

	// Create a new root key nonce.
	newRootKeyNonce, err = kr.generateNonce(rootKeyNonceSize)
	if err != nil {
		return RotateRootKeyResult{}, err
	}

	// Create a hash of the new root key plus nonce and encrypt it using the same key.
	newEncryptedRootKeyHash, err = newRootKey.EncryptedHash(newRootKeyNonce)
	if err != nil {
		return RotateRootKeyResult{}, err
	}

	// Set up the new keyring parameters.
	newParams := keyringParameters{
		uniqueID: kr.params.uniqueID,
		revision: kr.params.revision + 1,
	}
	if opts.ManualLock != nil {
		newParams.shares = uint8(opts.ManualLock.Shares)
		newParams.threshold = uint8(opts.ManualLock.Threshold)
	} else {
		newParams.usingAutoUnlock = true
	}

	// Save into the database.
	err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) error {
		err2 := isStorageInitialized(ctx, tx, &kr.params.uniqueID, &kr.params.revision)
		if err2 != nil {
			return err2
		}

		// Store the keyring parameters.
		err2 = newParams.SerializeToStorage(ctx, tx, pathKeyringParameters)
		if err2 != nil {
			return err2
		}

		if opts.ManualLock != nil {
			// Delete the encrypted root key. (It should not exist but....)
			err2 = tx.Delete(ctx, pathKeyringRootKey)
		} else {
			// Store the encrypted root key.
			err2 = tx.Put(ctx, pathKeyringRootKey, newEncryptedRootKey)
		}
		if err2 != nil {
			return err2
		}

		// Store the encrypted root key's hash.
		err2 = tx.Put(ctx, pathKeyringRootKeyHash, newEncryptedRootKeyHash)
		if err2 != nil {
			return err2
		}

		// Store the root key's nonce.
		err2 = tx.Put(ctx, pathKeyringRootKeyNonce, newRootKeyNonce)
		if err2 != nil {
			return err2
		}

		// Save encryption keys encrypted with the new root key.
		err2 = kr.writeEncryptionKeys(ctx, tx, newRootKey, kr.encryptionKeys, kr.activeEncryptionKeyID)

		// Done
		return err2
	})
	if err != nil {
		return RotateRootKeyResult{}, err
	}

	// Replace the keyring parameters.
	kr.params = newParams

	// Replace the root key.
	kr.rootKey.Zeroize()
	kr.rootKey = newRootKey
	newRootKey = nil

	// Done
	return ret, nil
}

// AddEncryptionKey adds a new encryption key to the keyring. Later encryption will use this new key.
func (kr *Keyring) AddEncryptionKey(ctx context.Context, engine string) error {
	var newEncryptionKeyID uint32
	var err error

	// Lock access.
	kr.mtx.Lock()
	defer kr.mtx.Unlock()

	// Check if the keyring is already unlocked.
	if !kr.isUnlocked() {
		return ErrLocked
	}

	// Generate a new encryption key.
	newEncryptionKeyID, err = kr.encryptionKeys.generateAndAddNewEncryptionKey(ctx, engine, kr.rg, kr.rootKey.ID)
	if err != nil {
		return err
	}

	// Increment revision.
	prevRevision := kr.params.revision
	kr.params.revision += 1

	// Save the new encryption key.
	err = kr.withinTx(ctx, false, func(ctx context.Context, tx StorageTx) (err error) {
		err = isStorageInitialized(ctx, tx, &kr.params.uniqueID, &prevRevision)
		if err != nil {
			return err
		}

		err = kr.params.SerializeToStorage(ctx, tx, pathKeyringParameters)
		if err != nil {
			return err
		}

		err = kr.writeNewEncryptionKey(ctx, tx, newEncryptionKeyID)
		return
	})
	if err != nil {
		// Before retuning, remove the newly created key.
		kr.encryptionKeys[newEncryptionKeyID].Zeroize()
		delete(kr.encryptionKeys, newEncryptionKeyID)

		// And restore the revision value
		kr.params.revision = prevRevision

		// Return error.
		return err
	}

	// Add the new key to the map and set as current.
	kr.activeEncryptionKeyID = newEncryptionKeyID

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

	// Check if the keyring is already unlocked.
	if !kr.isUnlocked() {
		return nil, ErrLocked
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

	// Check if the keyring is already unlocked.
	if !kr.isUnlocked() {
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
