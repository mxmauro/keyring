# keyring

A lightweight and secure keyring Golang library for managing secrets, passwords, and tokens across platforms.

## Features

* It uses Shamir's secret sharing for keyring initialization.
* Also supports an extensible auto-unlock feature. Easily pluggable to AWS CloudHSM or Azure Dedicated HSM.
* Supports multiple encryption engines (currently AES-GCM is implemented).
* Supports multiple encryption keys. New data is stored with the newest key. 
* Supports root key rotation.
* Supports a pluggable storage engine used to store keyring data.

## Usage

Create or open an existing keyring using the `New` function.

If the auto-unlock feature is enabled and the keyring is not initialized, the library will attempt to initialize
it automatically. If the keyring was already initialized, the library will attempt to unlock it.

In case of manual-unlock, use the keyring's `Initialize` method to initialize the keyring. It will create the
initial root and encryption keys and return the necessary information required to unlock the keyring in the future.
For this purpose, use the `InitUnlock` and `Unlock` methods.

Once the keyring is initialized and unlocked, you can start to encrypt and decrypt your data using the proper
methods.

## LICENSE

[MIT](/LICENSE)
