package keyring

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mxmauro/keyring/util"
)

// -----------------------------------------------------------------------------

// BeginStorageTransactionFunc defines a function that creates a transaction in the underlying storage.
type BeginStorageTransactionFunc func(ctx context.Context, readOnly bool) (StorageTx, error)

// StorageTx is an interface that represent a storage transaction.
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

func (kr *Keyring) readEncryptionKeys(ctx context.Context, tx StorageTx, masterKey *keyringKey) (keyringKeyMap, uint32, error) {
	var encryptedKey []byte
	var decryptedKey []byte

	cipher, err := masterKey.GetCipher()
	if err != nil {
		return nil, 0, err
	}

	keys := make(keyringKeyMap)

	// Zeroize on exit.
	success := false
	defer func() {
		util.SafeZeroMem(encryptedKey)
		util.SafeZeroMem(decryptedKey)
		if !success {
			for keyID := range keys {
				keys[keyID].Zeroize()
			}
			keys = nil
		}
	}()

	// Read keys.
	for idx := 1; ; idx++ {
		var kk *keyringKey

		encryptedKey, err = tx.Get(ctx, fmt.Sprintf(pathSystemEncryptionKeyFmt, idx))
		if err != nil {
			return nil, 0, err
		}
		if encryptedKey == nil {
			break // Last item reached.
		}

		decryptedKey, err = cipher.Decrypt(encryptedKey)
		if err != nil {
			return nil, 0, err
		}

		kk, err = deserializeKeyringKey(decryptedKey, kr.rg)
		if err != nil {
			return nil, 0, err
		}

		// Add to map.
		_, ok := keys[kk.ID]
		if kk.ID == masterKey.ID || ok {
			kk.Zeroize()
			return nil, 0, fmt.Errorf("duplicated encryption key with ID 0x%X", kk.ID)
		}
		keys[kk.ID] = kk
	}

	activeKeyID := uint32(0)
	if len(keys) > 0 {
		var activeKeyIdBytes []byte

		activeKeyIdBytes, err = tx.Get(ctx, pathSystemActiveEncryptionKeyID)
		if err != nil {
			return nil, 0, err
		}
		if len(activeKeyIdBytes) != idSize {
			return nil, 0, errors.New("invalid active encryption key ID")
		}
		activeKeyID = binary.LittleEndian.Uint32(activeKeyIdBytes)

		if _, ok := keys[activeKeyID]; !ok {
			return nil, 0, fmt.Errorf("active encription key with ID 0x%X not found", activeKeyID)
		}
	}

	// Done.
	success = true
	return keys, activeKeyID, nil
}

func (kr *Keyring) writeEncryptionKeys(ctx context.Context, tx StorageTx, masterKey *keyringKey, keys keyringKeyMap, activeKeyID uint32) error {
	var encryptedKey []byte
	var decryptedKey []byte

	cipher, err := masterKey.GetCipher()
	if err != nil {
		return err
	}

	// Zeroize on exit.
	defer func() {
		util.SafeZeroMem(encryptedKey)
		util.SafeZeroMem(decryptedKey)
	}()

	// Write keys.
	for idx, key := range keys {
		decryptedKey = key.Serialize()

		encryptedKey, err = cipher.Encrypt(decryptedKey)
		if err != nil {
			return err
		}

		err = tx.Put(ctx, fmt.Sprintf(pathSystemEncryptionKeyFmt, idx+1), encryptedKey)
		if err != nil {
			return err
		}

		idx += 1
	}

	// Delete next item if any.
	err = tx.Delete(ctx, fmt.Sprintf(pathSystemEncryptionKeyFmt, len(keys)+1))
	if err != nil {
		return err
	}

	// Write active key ID.
	buf := make([]byte, idSize)
	binary.LittleEndian.PutUint32(buf, keys[activeKeyID].ID)
	err = tx.Put(ctx, pathSystemActiveEncryptionKeyID, buf)
	if err != nil {
		return err
	}

	// Done.
	return nil
}

func (kr *Keyring) writeNewEncryptionKey(ctx context.Context, tx StorageTx, newKey *keyringKey) error {
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

	// Write key.
	decryptedKey = newKey.Serialize()

	encryptedKey, err = rootKeyCipher.Encrypt(decryptedKey)
	if err != nil {
		return err
	}

	err = tx.Put(ctx, fmt.Sprintf(pathSystemEncryptionKeyFmt, len(kr.encryptionKeys)+1), encryptedKey)
	if err != nil {
		return err
	}

	// Delete next item if any.
	err = tx.Delete(ctx, fmt.Sprintf(pathSystemEncryptionKeyFmt, len(kr.encryptionKeys)+2))
	if err != nil {
		return err
	}

	// Write active key ID.
	buf := make([]byte, idSize)
	binary.LittleEndian.PutUint32(buf, newKey.ID)
	err = tx.Put(ctx, pathSystemActiveEncryptionKeyID, buf)
	if err != nil {
		return err
	}

	// Done.
	return nil
}
