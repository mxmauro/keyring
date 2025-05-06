package keyring

// -----------------------------------------------------------------------------

const (
	dataVersion = 1
)

var (
	pathSystemParameters            = "system/parameters"
	pathSystemRootKey               = "system/root-key"
	pathSystemRootKeyHash           = "system/root-key-hash"
	pathSystemRootKeyNonce          = "system/root-key-nonce"
	pathSystemEncryptionKeyFmt      = "system/encryption-key-%d"
	pathSystemActiveEncryptionKeyID = "system/active-encryption-key-id"
)
