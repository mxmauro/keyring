package keyring

import (
	"context"
	"errors"

	bstd "github.com/deneonet/benc/std"
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
	bufSize := len(buf)
	if bufSize <= bstd.SizeUint16() {
		return keyringParameters{}, ErrInvalidStoredData
	}

	// Initialize parameters.
	kp := keyringParameters{}

	// Deserialize data.
	ofs, version, err := bstd.UnmarshalUint16(0, buf)
	if err != nil {
		return keyringParameters{}, ErrInvalidStoredData
	}
	switch version {
	case 1:
		ofs, kp.uniqueID, err = bstd.UnmarshalUint64(ofs, buf)
		if err != nil {
			return keyringParameters{}, ErrInvalidStoredData
		}
		ofs, kp.revision, err = bstd.UnmarshalUint32(ofs, buf)
		if err != nil {
			return keyringParameters{}, ErrInvalidStoredData
		}
		ofs, kp.usingAutoUnlock, err = bstd.UnmarshalBool(ofs, buf)
		if err != nil {
			return keyringParameters{}, ErrInvalidStoredData
		}
		ofs, kp.shares, err = bstd.UnmarshalByte(ofs, buf)
		if err != nil {
			return keyringParameters{}, ErrInvalidStoredData
		}
		ofs, kp.threshold, err = bstd.UnmarshalByte(ofs, buf)
		if err != nil {
			return keyringParameters{}, ErrInvalidStoredData
		}

	default:
		return keyringParameters{}, errors.New("unsupported keyring parameters version")
	}

	// Check if we reached the end of the buffer.
	if ofs != len(buf) {
		return keyringParameters{}, ErrInvalidStoredData
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
	bufSize := bstd.SizeUint16() +
		bstd.SizeUint64() +
		bstd.SizeUint32() +
		bstd.SizeBool() +
		bstd.SizeByte() +
		bstd.SizeByte()
	buf := make([]byte, bufSize)

	ofs := bstd.MarshalUint16(0, buf, keyringParametersVersion)
	ofs = bstd.MarshalUint64(ofs, buf, kp.uniqueID)
	ofs = bstd.MarshalUint32(ofs, buf, kp.revision)
	ofs = bstd.MarshalBool(ofs, buf, kp.usingAutoUnlock)
	ofs = bstd.MarshalByte(ofs, buf, kp.shares)
	ofs = bstd.MarshalByte(ofs, buf, kp.threshold)

	// Done
	return buf
}

func (kp *keyringParameters) SerializeToStorage(ctx context.Context, tx StorageTx, key string) error {
	return tx.Put(ctx, key, kp.Serialize())
}
