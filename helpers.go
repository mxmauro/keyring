package keyring

import (
	"context"
	"encoding/binary"
	"errors"
)

// -----------------------------------------------------------------------------

func (kr *Keyring) isUnlocked() bool {
	return kr.rootKey != nil
}

func (kr *Keyring) generateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)
	l, err := kr.rg.Read(nonce)
	if err != nil || l != size {
		return nil, errors.New("unable to generate nonce")
	}
	return nonce, nil
}

func (kr *Keyring) generateRandomUint64() (uint64, error) {
	var buf [8]byte

	_, err := kr.rg.Read(buf[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
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
