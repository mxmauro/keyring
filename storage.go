package keyring

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/mxmauro/keyring/util"
)

// -----------------------------------------------------------------------------

// BeginStorageTransactionFunc defines a function that creates a transaction in the underlying storage.
type BeginStorageTransactionFunc func(ctx context.Context, readOnly bool) (StorageTx, error)

// StorageTx is an interface that represents a storage transaction.
type StorageTx interface {
	// Get retrieves the value of the given key. Returns nil and no error if the key is not found.
	// Also, the implementation must return a copy of the value if the underlying implementation
	// overwrites its contents.
	Get(ctx context.Context, key string) ([]byte, error)

	// Put saves the given value under the provided key. The implementation MUST make a copy of the
	// value parameter if it needs to keep it until the commit call.
	Put(ctx context.Context, key string, value []byte) error

	// Delete removes the given key from the database. Don't return an error if the key is not found.
	Delete(ctx context.Context, key string) error

	// Commit saves all changes into the storage.
	Commit(ctx context.Context) error

	// Rollback discards pending changes.
	Rollback(ctx context.Context)
}

// -----------------------------------------------------------------------------

// IsKeyringKey returns true if the given key is a keyring key.
func IsKeyringKey(key string) bool {
	return isKeyringPath(key)
}

type withinTxCallback func(ctx context.Context, tx StorageTx) error

func (kr *Keyring) withinTx(ctx context.Context, readOnly bool, cb withinTxCallback) error {
	tx, err := kr.beginStgTx(ctx, readOnly)
	if err == nil {
		err = cb(ctx, tx)
		if err == nil {
			err = tx.Commit(ctx)
		}
		if err != nil {
			tx.Rollback(ctx)
		}
	}
	return err
}

func (kr *Keyring) readEncryptionKeys(ctx context.Context, tx StorageTx) ([][]byte, uint32, error) {
	encryptedKeys := make([][]byte, 0)

	// Zeroize on exit.
	success := false
	defer func() {
		if !success {
			util.SafeZeroMemArray(encryptedKeys)
		}
	}()

	// Read keys.
	for idx := 1; ; idx++ {
		encryptedKey, err := tx.Get(ctx, pathKeyringEncryptionKeyPrefix+strconv.Itoa(idx))
		if err != nil {
			return nil, 0, err
		}
		if encryptedKey == nil {
			break // Last item reached.
		}

		// Add to array
		encryptedKeys = append(encryptedKeys, encryptedKey)
	}

	// It should exist at least one encryption key.
	if len(encryptedKeys) == 0 {
		return nil, 0, ErrInvalidStoredData
	}

	// Read the active encryption key ID.
	activeKeyIdBytes, err := tx.Get(ctx, pathKeyringActiveEncryptionKeyID)
	if err != nil {
		return nil, 0, err
	}
	if len(activeKeyIdBytes) != idSize {
		return nil, 0, errors.New("invalid active encryption key ID")
	}
	activeKeyID := binary.LittleEndian.Uint32(activeKeyIdBytes)

	// Done.
	success = true
	return encryptedKeys, activeKeyID, nil
}

func (kr *Keyring) decryptEncryptionKeys(encryptedKeys [][]byte, rootKey *keyringKey) (keyringKeyMap, error) {
	var decryptedKey []byte

	cipher, err := rootKey.GetCipher()
	if err != nil {
		return nil, err
	}

	keys := make(keyringKeyMap)

	// Zeroize on exit.
	success := false
	defer func() {
		util.SafeZeroMem(decryptedKey)
		if !success {
			for keyID := range keys {
				keys[keyID].Zeroize()
			}
			keys = nil
		}
	}()

	// Read keys.
	for _, encryptedKey := range encryptedKeys {
		var kk *keyringKey

		decryptedKey, err = cipher.Decrypt(encryptedKey)
		if err != nil {
			return nil, err
		}

		kk, err = deserializeKeyringKey(decryptedKey, kr.rg)
		if err != nil {
			return nil, err
		}

		// Add to the map.
		_, ok := keys[kk.ID]
		if kk.ID == rootKey.ID || ok {
			kk.Zeroize()
			return nil, fmt.Errorf("duplicated encryption key with ID 0x%X", kk.ID)
		}
		keys[kk.ID] = kk
	}

	// Done
	success = true
	return keys, nil
}

func (kr *Keyring) writeEncryptionKeys(ctx context.Context, tx StorageTx, rootKey *keyringKey, encryptionKeys keyringKeyMap, activeKeyID uint32) error {
	var encryptedKey []byte
	var decryptedKey []byte

	cipher, err := rootKey.GetCipher()
	if err != nil {
		return err
	}

	// Zeroize on exit.
	defer func() {
		util.SafeZeroMem(encryptedKey)
		util.SafeZeroMem(decryptedKey)
	}()

	// Write keys.
	idx := 1
	for _, key := range encryptionKeys {
		decryptedKey = key.Serialize()

		encryptedKey, err = cipher.Encrypt(decryptedKey)
		if err != nil {
			return err
		}

		err = tx.Put(ctx, pathKeyringEncryptionKeyPrefix+strconv.Itoa(idx), encryptedKey)
		if err != nil {
			return err
		}

		idx += 1
	}

	// Delete next item if any.
	err = tx.Delete(ctx, pathKeyringEncryptionKeyPrefix+strconv.Itoa(idx))
	if err != nil {
		return err
	}

	// Write active key ID.
	buf := make([]byte, idSize)
	binary.LittleEndian.PutUint32(buf, activeKeyID)
	err = tx.Put(ctx, pathKeyringActiveEncryptionKeyID, buf)
	if err != nil {
		return err
	}

	// Done.
	return nil
}

func (kr *Keyring) writeNewEncryptionKey(ctx context.Context, tx StorageTx, newKeyID uint32) error {
	var encryptedKey []byte
	var decryptedKey []byte

	rootKeyCipher, err := kr.rootKey.GetCipher()
	if err != nil {
		return err
	}

	// Zeroize on exit.
	defer func() {
		util.SafeZeroMem(encryptedKey)
		util.SafeZeroMem(decryptedKey)
	}()

	// Get new key info.
	decryptedKey = kr.encryptionKeys[newKeyID].Serialize()
	keysCount := len(kr.encryptionKeys)

	// Write key.
	encryptedKey, err = rootKeyCipher.Encrypt(decryptedKey)
	if err != nil {
		return err
	}

	err = tx.Put(ctx, pathKeyringEncryptionKeyPrefix+strconv.Itoa(keysCount), encryptedKey)
	if err != nil {
		return err
	}

	// Delete next item if any.
	err = tx.Delete(ctx, pathKeyringEncryptionKeyPrefix+strconv.Itoa(keysCount+1))
	if err != nil {
		return err
	}

	// Write active key ID.
	buf := make([]byte, idSize)
	binary.LittleEndian.PutUint32(buf, newKeyID)
	err = tx.Put(ctx, pathKeyringActiveEncryptionKeyID, buf)
	if err != nil {
		return err
	}

	// Done.
	return nil
}

func isStorageInitialized(ctx context.Context, tx StorageTx, uniqueID *uint64, revision *uint32) error {
	params, err := deserializeKeyringParametersFromStorage(ctx, tx, pathKeyringParameters)
	if err != nil {
		if (uniqueID != nil || revision != nil) && errors.Is(err, ErrNotFound) {
			return ErrKeyringDataHasChanged
		}
		return err
	}
	if uniqueID != nil && revision != nil {
		if params.uniqueID != *uniqueID || params.revision != *revision {
			return ErrKeyringDataHasChanged
		}
	}
	return nil
}
