import pathlib
from azure.storage.blob import BlobClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_data(file, salt, key, base_folder, folder, iv, url):
    if file[0] == '.':
        return
    if file.endswith('.bkenc'):
        raise Exception(f'Error: cannot encrypt file {file}.')

    with open(folder + '/' + file, 'rb') as encrypt:
        data = encrypt.read()

    encrypted = AESGCM(key).encrypt(iv, data, None)
    encrypted = b'Salted__' + salt + encrypted

    # write new encrypted file, delete old
    with open(folder + '/' + file + ".bkenc", 'wb') as write:
        write.write(encrypted)

    upload_to_blob(url, folder + '/' + file + ".bkenc", base_folder)

    pathlib.Path(folder + '/' + file + ".bkenc").unlink()


def upload_to_blob(url, file, folder):
    uri = url.partition('?')
    new_uri = uri[0] + file.split(folder, 1)[1] + uri[1] + uri[2]
    client = BlobClient.from_blob_url(new_uri)

    with open(file, 'rb') as upload:
        client.upload_blob(upload, overwrite=True)