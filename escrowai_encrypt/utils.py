import pathlib
from azure.storage.blob import BlobClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt_data(file, salt, key, base_folder, folder, iv, url, n, count):
    if file[0] == '.':
        return 0
    if file.endswith('.bkenc'):
        raise Exception(f'Error: cannot encrypt file {file}.')
    
    print(f'Encrypting file {file} ({n}/{count})...')

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    chunk_size = 16 * 1024 * 1024 # 16 MB chunks
    with open(folder + '/' + file, 'rb') as encrypt, open(folder + '/' + file + ".bkenc", 'wb') as write:
        write.write(b'Salted__' + salt)

        bytes_processed = 0
        while True:
            chunk = encrypt.read(chunk_size)
            if not chunk:
                break

            encrypted = encryptor.update(chunk)
            write.write(encrypted)
            bytes_processed += len(chunk)

            del chunk
            del encrypted
    
        final_data = encryptor.finalize()
        write.write(final_data)
        tag = encryptor.tag
        write.write(tag)

    upload_to_blob(url, folder + '/' + file + ".bkenc", base_folder)

    pathlib.Path(folder + '/' + file + ".bkenc").unlink()

    print(f'Uploaded file {file + '.bkenc'} ({n}/{count}).')

    return 1


def upload_to_blob(url, file, folder):
    uri = url.partition('?')
    new_uri = uri[0] + file.split(folder, 1)[1] + uri[1] + uri[2]
    client = BlobClient.from_blob_url(new_uri)

    with open(file, 'rb') as upload:
        client.upload_blob(upload, overwrite=True)