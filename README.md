# escrowai-encrypt

A module for encryption of artifacts and keys to be uploaded to EscrowAI.

## Overview

The escrowai-encrypt module provides tools for encrypting algorithms, datasets, and managing encryption keys for use with EscrowAI. It implements secure encryption practices using AES-GCM for data encryption and RSA-OAEP for key wrapping.

## Requirements

- Python >= 3.6
- Dependencies:
  - azure-storage-blob
  - cryptography
  - pyyaml

## Installation

```bash
pip install escrowai-encrypt
```

## Function Reference

### Key Management Functions

#### `generate_content_encryption_key(filename='')`
Generates a new Content Encryption Key (CEK) used for encrypting algorithms and datasets.

**Parameters:**
- `filename` (str, optional): Path where the CEK will be saved. If not provided, generates a random filename.

**Returns:** None

**Output:** Creates a file containing a 32-byte random key.

**Usage:**
```python
from escrowai_encrypt.encryption import generate_content_encryption_key

# Generate a new CEK with random filename
generate_content_encryption_key()

# Generate a new CEK with specific filename
generate_content_encryption_key('my_cek.key')
```

#### `generate_wrapped_content_encryption_key(content_encryption_key, key_encryption_key, filename='')`
Wraps a CEK using a Key Encryption Key (KEK) for secure storage and transmission.

**Parameters:**
- `content_encryption_key` (str): Path to the CEK file
- `key_encryption_key` (str): Path to the KEK file (RSA public key in PEM format)
- `filename` (str, optional): Output path for the wrapped key

**Returns:** None

**Output:** Creates a file containing the wrapped CEK

**Usage:**
```python
from escrowai_encrypt.encryption import generate_wrapped_content_encryption_key

# Wrap a CEK with a KEK
generate_wrapped_content_encryption_key(
    content_encryption_key='my_cek.key',
    key_encryption_key='my_kek.pem'
)
```

### Algorithm Encryption Functions

#### `encrypt_algorithm(algorithm_directory, content_encryption_key, filename='')`
Encrypts an algorithm directory and its secrets.

**Parameters:**
- `algorithm_directory` (str): Path to the algorithm directory
- `content_encryption_key` (str): Path to the CEK file
- `filename` (str, optional): Output path for the encrypted algorithm zip file

**Returns:** None

**Output:** Creates a zip file containing the encrypted algorithm

**Usage:**
```python
from escrowai_encrypt.encryption import encrypt_algorithm

# Encrypt an algorithm directory
encrypt_algorithm(
    algorithm_directory='path/to/algorithm',
    content_encryption_key='my_cek.key'
)
```

### Dataset Encryption Functions

#### `encrypt_upload_dataset(dataset_directory, content_encryption_key, dataset_sas_uri)`
Encrypts and uploads a local dataset to Azure Blob Storage.

**Parameters:**
- `dataset_directory` (str): Path to the dataset directory
- `content_encryption_key` (str): Path to the CEK file
- `dataset_sas_uri` (str): Azure Blob Storage SAS URI for upload

**Returns:** None

**Output:** Uploads encrypted files to the specified blob storage

**Usage:**
```python
from escrowai_encrypt.encryption import encrypt_upload_dataset

# Encrypt and upload a local dataset
encrypt_upload_dataset(
    dataset_directory='path/to/dataset',
    content_encryption_key='my_cek.key',
    dataset_sas_uri='https://storage-account.blob.core.windows.net/container?sv=...'
)
```

#### `encrypt_upload_dataset_from_blob(dataset_sas_uri_unencrypted, content_encryption_key, dataset_sas_uri)`
Encrypts and uploads a dataset from one blob storage to another.

**Parameters:**
- `dataset_sas_uri_unencrypted` (str): Source blob storage SAS URI
- `content_encryption_key` (str): Path to the CEK file
- `dataset_sas_uri` (str): Target blob storage SAS URI

**Returns:** None

**Output:** Downloads, encrypts, and uploads files to the target blob storage

**Usage:**
```python
from escrowai_encrypt.encryption import encrypt_upload_dataset_from_blob

# Encrypt and upload a dataset from one blob storage to another
encrypt_upload_dataset_from_blob(
    dataset_sas_uri_unencrypted='https://source-storage.blob.core.windows.net/container?sv=...',
    content_encryption_key='my_cek.key',
    dataset_sas_uri='https://target-storage.blob.core.windows.net/container?sv=...'
)
```

### Decryption Functions

#### `decrypt_secret(secret, content_encryption_key, filename='')`
Decrypts an encrypted secret file.

**Parameters:**
- `secret` (str): Path to the encrypted secret file
- `content_encryption_key` (str): Path to the CEK file
- `filename` (str, optional): Output path for the decrypted secret

**Returns:** None

**Output:** Creates a file containing the decrypted secret

**Usage:**
```python
from escrowai_encrypt.decryption import decrypt_secret

# Decrypt an encrypted secret
decrypt_secret(
    secret='encrypted_secret.bkenc',
    content_encryption_key='my_cek.key'
)
```

## Security Notes

- All encryption uses AES-GCM with a 256-bit key
- Key wrapping uses RSA-OAEP with SHA-1
- PBKDF2 is used for key derivation with 10,000 iterations
- All encrypted files are prefixed with 'Salted__' and include a random salt
- Files are processed in 16MB chunks to handle large datasets efficiently

## License

MIT License
