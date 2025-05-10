package keyring

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash/fnv"
	"io"
	"sync"
	"time"

	bstd "github.com/deneonet/benc/std"
	"github.com/mxmauro/keyring/crypto/ciphers"
	"github.com/mxmauro/keyring/models"
	"github.com/mxmauro/keyring/util"
	"github.com/mxmauro/shamir"
)

// -----------------------------------------------------------------------------

const (
	keyringKeyVersion = 1

	idSize = 4
)

// -----------------------------------------------------------------------------

type keyringKey struct {
	ID           uint32
	Engine       string
	Key          []byte
	CreationTime time.Time

	rg     io.Reader
	cipher models.Cipher
}

type keyringKeyMap map[uint32]*keyringKey

// -----------------------------------------------------------------------------

var getCipherMtx = sync.Mutex{}

// -----------------------------------------------------------------------------

func generateKeyringKey(engine string, rg io.Reader) (*keyringKey, error) {
	// Generate a new key.
	key, err := ciphers.GenerateKey(engine, rg)
	if err != nil {
		return nil, err
	}

	// Get current timestamp
	now := time.Now().UTC()

	// Create ID.
	h := fnv.New32a()
	_, _ = h.Write(key)
	_, _ = h.Write([]byte(now.String()))
	id := h.Sum32()

	// Create the new keyring key.
	kk := keyringKey{
		ID:           id,
		Engine:       engine,
		Key:          key,
		CreationTime: now,
		rg:           rg,
	}

	// Done
	return &kk, nil
}

func deserializeKeyringKey(buf []byte, rg io.Reader) (*keyringKey, error) {
	var ct int64

	bufSize := len(buf)
	if bufSize <= bstd.SizeUint16() {
		return nil, ErrInvalidStoredData
	}

	// Initialize key.
	kk := keyringKey{
		rg: rg,
	}

	success := false
	defer func() {
		if !success {
			kk.Zeroize()
		}
	}()

	// Deserialize data.
	ofs, version, err := bstd.UnmarshalUint16(0, buf)
	if err != nil {
		return nil, ErrInvalidStoredData
	}
	switch version {
	case 1:
		ofs, kk.ID, err = bstd.UnmarshalUint32(ofs, buf)
		if err != nil {
			return nil, ErrInvalidStoredData
		}
		ofs, kk.Engine, err = bstd.UnmarshalString(ofs, buf)
		if err != nil {
			return nil, ErrInvalidStoredData
		}
		ofs, kk.Key, err = bstd.UnmarshalBytesCopied(ofs, buf)
		if err != nil {
			return nil, ErrInvalidStoredData
		}
		ofs, ct, err = bstd.UnmarshalInt64(ofs, buf)
		kk.CreationTime = time.Unix(ct, 0).UTC()

	default:
		return nil, errors.New("unsupported keyring key version")
	}

	// Check if we reached the end of the buffer.
	if ofs != len(buf) {
		return nil, ErrInvalidStoredData
	}

	// CHeck if the engine is supported.
	if !ciphers.IsEngineSupported(kk.Engine) {
		return nil, ciphers.ErrEngineNotSupported
	}

	// Done
	success = true
	return &kk, nil
}

func (kk *keyringKey) Zeroize() {
	kk.ID = 0
	kk.Engine = ""
	util.SafeZeroMem(kk.Key)
	kk.CreationTime = time.Time{}

	kk.rg = nil
}

func (kk *keyringKey) Serialize() []byte {
	bufSize := bstd.SizeUint16() + bstd.SizeString(kk.Engine) + bstd.SizeUint32() + bstd.SizeBytes(kk.Key) + bstd.SizeUint64()
	buf := make([]byte, bufSize)

	ofs := bstd.MarshalUint16(0, buf, keyringKeyVersion)
	ofs = bstd.MarshalUint32(ofs, buf, kk.ID)
	ofs = bstd.MarshalString(ofs, buf, kk.Engine)
	ofs = bstd.MarshalBytes(ofs, buf, kk.Key)
	ofs = bstd.MarshalInt64(ofs, buf, kk.CreationTime.Unix())

	// Done
	return buf
}

func (kk *keyringKey) SerializeToStorage(ctx context.Context, tx StorageTx, key string) error {
	return tx.Put(ctx, key, kk.Serialize())
}

func (kk *keyringKey) GetCipher() (models.Cipher, error) {
	if kk.cipher == nil {
		getCipherMtx.Lock()
		defer getCipherMtx.Unlock()

		if kk.cipher == nil {
			cipher, err := ciphers.NewFromKey(kk.Engine, kk.Key, kk.rg)
			if err != nil {
				return nil, err
			}
			kk.cipher = cipher
		}
	}
	return kk.cipher, nil
}

func (kk *keyringKey) Hash(nonce []byte) []byte {
	idBuf := make([]byte, idSize)
	binary.LittleEndian.PutUint32(idBuf, kk.ID)

	h := sha512.New()
	_, _ = h.Write(kk.Key)
	_, _ = h.Write(idBuf)
	_, _ = h.Write(nonce)
	return h.Sum(nil)
}

func (kk *keyringKey) EncryptedHash(nonce []byte) ([]byte, error) {
	cipher, err := kk.GetCipher()
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(kk.Hash(nonce))
}

func (kk *keyringKey) ValidateEncryptedHash(encryptedHash []byte, nonce []byte) (bool, error) {
	var decryptedHash []byte

	cipher, err := kk.GetCipher()
	if err != nil {
		return false, err
	}
	decryptedHash, err = cipher.Decrypt(encryptedHash)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(kk.Hash(nonce), decryptedHash) != 1 {
		return false, nil
	}
	return true, nil
}

func (kk *keyringKey) Split(shares int, threshold int) ([][]byte, error) {
	if shares == 1 {
		split := make([][]byte, 1)
		split[0] = kk.Serialize()
		return split, nil
	}
	// Split the key using the Shamir algorithm.
	return shamir.Split(kk.Serialize(), shares, threshold)
}

func (km *keyringKeyMap) containsID(id uint32) bool {
	_, ok := (*km)[id]
	return ok
}

func (km *keyringKeyMap) generateAndAddNewEncryptionKey(ctx context.Context, engine string, rg io.Reader, rootKeyID uint32) (uint32, error) {
	for {
		newEncryptionKey, err := generateKeyringKey(engine, rg)
		if err != nil {
			return 0, err
		}

		if newEncryptionKey.ID != rootKeyID && !km.containsID(newEncryptionKey.ID) {
			(*km)[newEncryptionKey.ID] = newEncryptionKey
			return newEncryptionKey.ID, nil
		}

		newEncryptionKey.Zeroize()

		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
