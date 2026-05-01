package keyring

import (
	"context"
	"errors"

	bstd "github.com/mxmauro/bencstd-compat"
)

// -----------------------------------------------------------------------------

const (
	keyringParametersVersion = 1
)

// -----------------------------------------------------------------------------

type keyringParameters struct {
	uniqueID        uint64
	revision        uint32 // This field is incremented on every change.
	usingAutoUnlock bool
	shares          uint8
	threshold       uint8
}

// -----------------------------------------------------------------------------

func deserializeKeyringParameters(buf []byte) (keyringParameters, error) {
	// Initialize parameters.
	kp := keyringParameters{}

	// Deserialize data.
	if len(buf) < 2 {
		return keyringParameters{}, ErrInvalidStoredData
	}

	dec := bstd.NewDecoder(buf)
	version := dec.Uint16()
	if dec.Err() != nil {
		return keyringParameters{}, ErrInvalidStoredData
	}

	switch version {
	case 1:
		kp.uniqueID = dec.Uint64()
		kp.revision = dec.Uint32()
		kp.usingAutoUnlock = dec.Bool()
		kp.shares = dec.Byte()
		kp.threshold = dec.Byte()
		if dec.Err() != nil || dec.Remaining() != 0 {
			return keyringParameters{}, ErrInvalidStoredData
		}

	default:
		return keyringParameters{}, errors.New("unsupported keyring parameters version")
	}

	// Done
	return kp, nil
}

func deserializeKeyringParametersFromStorage(ctx context.Context, tx StorageTx, key string) (keyringParameters, error) {
	var params keyringParameters

	// Get encoded parameters from storage.
	encodedParams, err := tx.Get(ctx, key)
	if err != nil {
		return keyringParameters{}, err
	}
	if encodedParams == nil {
		return keyringParameters{}, ErrNotFound
	}

	// Deserialize it.
	params, err = deserializeKeyringParameters(encodedParams)
	if err != nil {
		return keyringParameters{}, err
	}

	// Done
	return params, nil
}

func (kp *keyringParameters) Serialize() []byte {
	enc := bstd.NewDynamicEncoder(32)

	enc.Uint16(keyringParametersVersion)
	enc.Uint64(kp.uniqueID)
	enc.Uint32(kp.revision)
	enc.Bool(kp.usingAutoUnlock)
	enc.Byte(kp.shares)
	enc.Byte(kp.threshold)
	if enc.Err() != nil {
		return nil
	}

	// Done
	return enc.Bytes()
}

func (kp *keyringParameters) SerializeToStorage(ctx context.Context, tx StorageTx, key string) error {
	return tx.Put(ctx, key, kp.Serialize())
}
