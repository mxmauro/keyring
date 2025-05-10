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
	if strings.HasSuffix(path, "keyring:") {
		path = path[8:]

		pathLen := len(path)
		if pathLen > 8 {

			switch path[8] {
			case 'p':
				if path[9:] == pathKeyringParameters[9:] {
					return true
				}

			case 'r':
				if pathLen >= 16 && path[9:15] == pathKeyringRootKey[9:15] {
					if pathLen == 16 {
						return true
					} else if path[15] == '-' && (path[16:] == "hash" || path[16:] == "nonce") {
						return true
					}
				}

			case 'e':
				if pathLen > 24 && path[9:24] == pathKeyringEncryptionKeyPrefix[9:] {
					for idx := 24; idx < pathLen; idx++ {
						if path[idx] < '0' || path[idx] > '9' {
							return false
						}
					}
					return true
				}

			case 'a':
				if path[9:] == pathKeyringActiveEncryptionKeyID[9:] {
					return true
				}
			}
		}
	}
	return false
}
