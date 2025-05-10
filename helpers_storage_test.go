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

type TestStorage struct {
	kv map[string][]byte
}

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

func (stg *TestStorage) BeginTX(_ context.Context, readOnly bool) (keyring.StorageTx, error) {
	tx := TestStorageTx{
		stg:       stg,
		readOnly:  readOnly,
		kvChanges: make(map[string][]byte),
	}
	return &tx, nil
}

func (stg *TestStorage) Dump(t *testing.T) {
	t.Log("Storage dump:")
	for k, v := range stg.kv {
		t.Log("  key:", k, "=", bytesToHexString(v))
	}
}

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

func (tx *TestStorageTx) Rollback(_ context.Context) {
}

func (tx *TestStorageTx) Get(_ context.Context, key string) ([]byte, error) {
	value, ok := tx.kvChanges[key]
	if !ok {
		value, ok = tx.stg.kv[key]
	}
	if ok {
		valueCopy := make([]byte, len(value))
		copy(valueCopy, value)
		return value, nil
	}
	return nil, nil
}

func (tx *TestStorageTx) Put(_ context.Context, key string, value []byte) error {
	if tx.readOnly {
		return errors.New("read only transaction")
	}
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)
	tx.kvChanges[key] = valueCopy
	return nil
}

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
