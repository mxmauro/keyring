package keyring

import (
	"strings"
)

// -----------------------------------------------------------------------------

const (
	dataVersion = 1
)

var (
	pathKeyringParameters            = "keyring:parameters"
	pathKeyringRootKey               = "keyring:root-key"
	pathKeyringRootKeyHash           = "keyring:root-key-hash"
	pathKeyringRootKeyNonce          = "keyring:root-key-nonce"
	pathKeyringEncryptionKeyPrefix   = "keyring:encryption-key-"
	pathKeyringActiveEncryptionKeyID = "keyring:active-encryption-key-id"
)

// -----------------------------------------------------------------------------

func isKeyringPath(path string) bool {
	if path == pathKeyringParameters || path == pathKeyringRootKey || path == pathKeyringRootKeyHash {
		return true
	}
	if path == pathKeyringRootKeyNonce || path == pathKeyringActiveEncryptionKeyID {
		return true
	}

	if !strings.HasPrefix(path, pathKeyringEncryptionKeyPrefix) {
		return false
	}

	idx := path[len(pathKeyringEncryptionKeyPrefix):]
	if len(idx) == 0 {
		return false
	}

	for _, c := range idx {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}
