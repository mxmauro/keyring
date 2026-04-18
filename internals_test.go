package keyring

import "testing"

// -----------------------------------------------------------------------------

func TestIsKeyringPath(t *testing.T) {
	validKeys := []string{
		pathKeyringParameters,
		pathKeyringRootKey,
		pathKeyringRootKeyHash,
		pathKeyringRootKeyNonce,
		pathKeyringActiveEncryptionKeyID,
		pathKeyringEncryptionKeyPrefix + "1",
		pathKeyringEncryptionKeyPrefix + "123",
	}
	for _, key := range validKeys {
		if !isKeyringPath(key) {
			t.Fatalf("expected keyring path %q to be valid", key)
		}
	}

	invalidKeys := []string{
		"",
		"keyring:",
		"keyring:unknown",
		pathKeyringEncryptionKeyPrefix,
		pathKeyringEncryptionKeyPrefix + "x",
		pathKeyringEncryptionKeyPrefix + "-1",
		"prefix:" + pathKeyringParameters,
	}
	for _, key := range invalidKeys {
		if isKeyringPath(key) {
			t.Fatalf("expected keyring path %q to be invalid", key)
		}
	}
}
