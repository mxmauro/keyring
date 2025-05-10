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

Create a keyring object using the `New` function.

Then use `Initialize` method to initialize the keyring. It will create the initial root and encryption keys and return
the necessary information required to unlock the keyring in the future.

#### NOTES:

* It is safe to call `Initialize` in an already initialized keyring, the proper error (`ErrAlreadyInitialized`) will
  be returned.
* On a successful call to `Initialize`, the keyring is left unlocked. See the [locking](#locking) section below for
  details.

At this point you can use `Encrypt` and `Decrypt` to encrypt and decrypt data.

## Locking

When an already initialized keyring object is created, the keyring remains in a **locked** state.

To unlock the keyring, use the `Unlock` method and pass the proper parameter options depending if manual or
automatic unlock mechanism is being used.

Once the keyring is unlocked, you can, again, use `Encrypt` and `Decrypt` to encrypt and decrypt data. 

### Manual lock

In manual lock/unlock mode, the `Initialize` method returns a set of keys that SHOULD be distributed among several
parties. Every call to `Unlock` needs a key until the configured threshold is reached and the keyring will be 
unlocked.

### Automatic lock

In automatic lock/unlock mode, an encryption/decryption callback function is passed as the parameter. The engine
will call them to encrypt or decrypt the root key.

This approach is mainly intended to be used with third-party Hardware Security Modules (HSM) like AWS CloudHSM and
Azure KeyVault, but you can also use your custom solution.

Because this method does not involves different parties having just one piece of the whole key, BE VERY CAREFUL
about how has access and how the chosen engine works to avoid unauthorized access.

## Bugs and enhancements

Don't hesitate to open a GitHub issue if you find any bug or want to share any improvement.

#### NOTES:

* Access to HSM engines in the cloud and databases are not and won't be part of this library.

* Multiple instances of an application using the same storage for the keyring should work without problems. The
  `Status` method can be called from time to time to detect if the keyring object should be recreated on a given
  instance due to a change. Because existing encryption keys are never deleted, an instance can still work if it
  is "outdated."

* If several instances are running but, each one, with their own storage and they are synchronized through, for
  example, some consensus mechanism like Raft. In this case, the recommended approach would to capture all the
  changes between the `BeginStorageTransactionFunc` call and its commit, and group them as a single operation.

  Even a root key rotation involving rewriting hundreds of stored encryption keys, the whole operation should
  take a few kilobytes of data.

## LICENSE

Copyright © 2025 Mauro H. Leggieri

[MIT](/LICENSE)
