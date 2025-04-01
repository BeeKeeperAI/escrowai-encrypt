import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_secret(secret: str, content_encryption_key: str, filename=''):
    '''
    Decrypt an encrypted secret file using the Content Encryption Key (CEK) it was
    encrypted with.
    '''
    if filename == '':
        split = secret.split('.')
        if 'bkenc' in split:
            split.remove('bkenc')
        split.insert(1, '_unencrypted.')
        filename = ''.join(split)

    with open(content_encryption_key, 'rb') as key_file:
        password = key_file.read()

    # Get file size to determine where the tag is
    file_size = os.path.getsize(secret)
    tag_size = 16  # GCM tag is 16 bytes

    with open(secret, 'rb') as infile:
        # Read header and salt
        header = infile.read(16)  # 'Salted__' + 8 bytes salt

        # Check for the "Salted__" prefix
        if not header.startswith(b'Salted__'):
            raise ValueError("Invalid encrypted file format or missing 'Salted__' prefix.")

        salt = header[8:16]  # Extract salt

        # Derive key from password and salt using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32 + 12,  # 32 bytes for AES key and 12 for nonce
            salt=salt,
            iterations=10000,
            backend=default_backend()
        )
        derived_key = kdf.derive(password)
        key = derived_key[:32]
        nonce = derived_key[32:44]

        # Read the tag from the end of the file
        infile.seek(file_size - tag_size)
        tag = infile.read(tag_size)

        # Calculate data size (excluding header and tag)
        data_size = file_size - 16 - tag_size

        # Reset to after the header for decryption
        infile.seek(16)

        # Initialize cipher with the tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()

        # Chunk size for processing large files
        chunk_size = 16 * 1024 * 1024  # 16MB chunks

        print(f'Decrypting secret {secret} as {filename}...')
        with open(filename, 'wb') as outfile:
            bytes_processed = 0
            while bytes_processed < data_size:
                remaining = data_size - bytes_processed
                current_chunk_size = min(chunk_size, remaining)
                ciphertext = infile.read(current_chunk_size)
                plaintext = decryptor.update(ciphertext)
                outfile.write(plaintext)
                bytes_processed += len(ciphertext)

                # Explicitly delete variables to help with garbage collection
                del ciphertext
                del plaintext

            # Finalize decryption
            final_plaintext = decryptor.finalize()
            outfile.write(final_plaintext)
    
    print(f'Secret successfully decrypted as {filename}.')
