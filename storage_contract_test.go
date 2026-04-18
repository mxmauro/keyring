package keyring_test

import (
	"context"
	"testing"
)

// -----------------------------------------------------------------------------

func TestStorageGetReturnsCopy(t *testing.T) {
	ctx := context.Background()
	stg := newTestStorage()

	tx, err := stg.BeginTX(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Put(ctx, "sample", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	readTx, err := stg.BeginTX(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	value, err := readTx.Get(ctx, "sample")
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 99
	readTx.Rollback(ctx)

	verifyTx, err := stg.BeginTX(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	defer verifyTx.Rollback(ctx)

	value, err = verifyTx.Get(ctx, "sample")
	if err != nil {
		t.Fatal(err)
	}
	if value[0] != 1 {
		t.Fatalf("storage returned aliased data: got %d want 1", value[0])
	}
}
