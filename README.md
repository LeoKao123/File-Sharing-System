# End-to-End Encrypted File Sharing System

This repository contains the implementation for a secure file-sharing system reminiscent of Dropbox, but enhanced with robust cryptographic protection to prevent unauthorized server access or tampering with the stored data.

## Table of Contents

1. [Implementation Details](#implementation-details)
2. [Project Features](#project-features)
3. [Servers Used](#servers-used)
4. [Cryptographic Utilities](#cryptographic-utilities)

## Implementation Details

- **Main Implementation:** `client/client.go`
  
- **Unit Tests:** `client_test/client_test.go`

To run unit tests, navigate to the `client_test` directory and execute:
```
go test -v
```

## Project Features

The client, developed in Golang, supports several operations:

1. User authentication via username and password.
2. Saving files to the server.
3. Retrieving saved files from the server.
4. Overwriting files on the server.
5. Appending to saved files on the server.
6. Sharing files with other users.
7. Revoking access to shared files.

## Servers Used

The application interfaces with two servers: the **Keystore** and the **Datastore**.

- **Keystore**: A trusted server where users can publish their public keys. It functions as a key-value store, where the "key" is a unique identifier used for indexing, not a cryptographic key. Attackers cannot overwrite any client entry in the Keystore.

- **Datastore**: An untrusted server providing persistent storage. Like the Keystore, it uses a key-value structure with "key" as a unique identifier. The Datastore does not conduct any access control, so any entry can be overwritten or deleted by a user with knowledge of the appropriate storage key.

## Cryptographic Utilities

The project leverages various cryptographic algorithms and functions to interact with both the Keystore and Datastore. These utilities are encapsulated within the `userlib` and are imported into `client.go`.

The following cryptographic algorithms and techniques are employed:
Public Key Encryption (PKE)\
Digital Signatures (DS)\
Hash Functions\
Hash-Based Message Authentication Code (HMAC)\
Hash-Based Key Derivation Function (HKDF)\
Password-Based Key Derivation Function\
Symmetric Encryption\

---
