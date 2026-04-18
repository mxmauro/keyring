package keyring_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mxmauro/keyring"
)

// -----------------------------------------------------------------------------

// TestStorage is an in-memory storage backend used by the tests.
type TestStorage struct {
	kv map[string][]byte
}

// TestStorageTx is a transactional view over TestStorage used by the tests.
type TestStorageTx struct {
	stg       *TestStorage
	readOnly  bool
	kvChanges map[string][]byte
}

// -----------------------------------------------------------------------------

func newTestStorage() *TestStorage {
	return &TestStorage{
		kv: make(map[string][]byte),
	}
}

// BeginTX starts a new in-memory transaction for tests.
func (stg *TestStorage) BeginTX(_ context.Context, readOnly bool) (keyring.StorageTx, error) {
	tx := TestStorageTx{
		stg:       stg,
		readOnly:  readOnly,
		kvChanges: make(map[string][]byte),
	}
	return &tx, nil
}

// Dump writes the current storage contents to the test log.
func (stg *TestStorage) Dump(t *testing.T) {
	t.Log("Storage dump:")
	for k, v := range stg.kv {
		t.Log("  key:", k, "=", bytesToHexString(v))
	}
}

// Commit applies the pending transaction changes to the backing storage.
func (tx *TestStorageTx) Commit(_ context.Context) error {
	for k, v := range tx.kvChanges {
		if v != nil {
			tx.stg.kv[k] = v
		} else {
			delete(tx.stg.kv, k)
		}
	}
	return nil
}

// Rollback discards the pending transaction changes.
func (tx *TestStorageTx) Rollback(_ context.Context) {
}

// Get returns a copy of the stored value for key.
func (tx *TestStorageTx) Get(_ context.Context, key string) ([]byte, error) {
	value, ok := tx.kvChanges[key]
	if !ok {
		value, ok = tx.stg.kv[key]
	}
	if ok {
		valueCopy := make([]byte, len(value))
		copy(valueCopy, value)
		return valueCopy, nil
	}
	return nil, nil
}

// Put stores a copy of value in the transaction.
func (tx *TestStorageTx) Put(_ context.Context, key string, value []byte) error {
	if tx.readOnly {
		return errors.New("read only transaction")
	}
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	tx.kvChanges[key] = valueCopy
	return nil
}

// Delete marks key for removal when the transaction commits.
func (tx *TestStorageTx) Delete(_ context.Context, key string) error {
	tx.kvChanges[key] = nil
	return nil
}

func bytesToHexString(data []byte) string {
	var builder strings.Builder

	for idx, b := range data {
		if idx > 0 {
			_, _ = builder.WriteString(", ")
		}
		_, _ = builder.WriteString(fmt.Sprintf("0x%02x", b))
	}
	return builder.String()
}
