import os
import uuid
import yaml
import pathlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from zipfile import ZipFile
from azure.storage.blob import ContainerClient
from escrowai_encrypt.utils import encrypt_data
import shutil


def generate_content_encryption_key(filename=''):
    '''
    Generate a Content Encryption Key (CEK), the key used to encrypt an algorithm or dataset.
    '''

    if filename == '':
        filename = f'cek_{uuid.uuid4()}.key'
    
    with open(filename, 'wb') as file:
        file.write(os.urandom(32))
    
    print(f'Content Encryption Key (CEK) downloaded successfully to {filename}.')


def generate_wrapped_content_encryption_key(content_encryption_key: str, key_encryption_key: str, filename=''):
    '''
    Generate a Wrapped Content Encryption Key (WCEK), a Content Encryption Key (CEK) that has been encrypted
    using a Key Encryption Key (KEK).
    '''

    if filename == '':
        filename = f'wcek_{uuid.uuid4()}.key.bkenc'

    with open(content_encryption_key, 'rb') as file:
        cek = file.read()
    with open(key_encryption_key, 'rb') as file:
        kek = file.read()
    
    print(f'Wrapping CEK {content_encryption_key} with KEK {key_encryption_key} to file {filename}...')

    public_key = load_pem_public_key(kek, backend=default_backend())
    encrypted = public_key.encrypt(
        cek,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    with open(filename, 'wb') as file:
        file.write(encrypted)

    print(f'Wrapped Content Encryption Key (WCEK) downloaded successfully to {filename}.')


def encrypt_algorithm(algorithm_directory: str, content_encryption_key: str, filename=''):
    '''
    Encrypt an Algorithm. Algorithm encryption safeguards your algorithm during storage, transmission, 
    and execution. The algorithm is encrypted using a Content Encryption Key (CEK).
    '''

    if filename == '':
        filename = f'{algorithm_directory}_encrypted_{uuid.uuid4()}.zip'
    
    with open(content_encryption_key, 'rb') as file:
        cek = file.read()

    original_files = []
    new_files = []
    with open(f'{algorithm_directory}/secrets.yaml', 'r') as f:
        files = yaml.safe_load(f)

    count = str(len(files['secretFiles']))
    n = 1

    print(f'{count} secret(s) to be encrypted.')
    for f in files['secretFiles']:
        print(f'Encrypting secret {f[1]} ({n}/{count})...')
        newpaths = ['', '']
        newpaths[0] = f'{algorithm_directory}/{f[0]}'
        newpaths[1] = f'{algorithm_directory}/{f[1]}'

        salt = os.urandom(8)
        pbkdf2_hash = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            length=32 + 12,
            iterations=10000,
            backend=default_backend()
        )

        derived_password = pbkdf2_hash.derive(cek)
        key = derived_password[0:32]
        iv = derived_password[32:(32 + 12)]

        with open(newpaths[1], 'rb') as encrypt:
            data = encrypt.read()

        encrypted = AESGCM(key).encrypt(iv, data, None)
        encrypted = b'Salted__' + salt + encrypted

        with open(newpaths[0], 'wb') as write:
            write.write(encrypted)
        
        original_files.append(f[1])
        new_files.append(newpaths[0])

        print(f'Secret {f[0]} encrypted ({n}/{count}).')

    shutil.make_archive('temp', 'zip', algorithm_directory)
    for i in new_files:
        pathlib.Path(i).unlink()

    zip_in = ZipFile('temp.zip', 'r')
    zip_out = ZipFile(filename, 'w')

    for item in zip_in.infolist():
        buffer = zip_in.read(item.filename)
        if item.filename not in original_files:
            zip_out.writestr(item, buffer)
    zip_in.close()
    zip_out.close()

    pathlib.Path('temp.zip').unlink()

    print(f'Algorithm successfully encrypted as {filename}.')


def encrypt_upload_dataset(dataset_directory: str, content_encryption_key: str, dataset_sas_uri: str):
    '''
    Encrypt and upload a Dataset to Azure Blob Storage. Dataset encryption safeguards your dataset during storage, 
    transmission, and execution. The dataset is encrypted using a Content Encryption Key (CEK) and uploaded using
    a Shared Access Signature (SAS) URL.
    '''

    with open(content_encryption_key, 'rb') as file:
        cek = file.read()

    salt = os.urandom(8)
    pbkdf2_hash = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32 + 12,
        iterations=10000,
        backend=default_backend()
    )

    derived_password = pbkdf2_hash.derive(cek)
    key = derived_password[0:32]
    iv = derived_password[32:(32 + 12)]

    count = sum(len([x for x in files if x[0] != '.']) for _, _, files in os.walk(dataset_directory))
    n = 1

    print(f'{count} files(s) to be encrypted and uploaded.')
    for root, _, files in os.walk(dataset_directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            dirname = os.path.dirname(file_path)
            n += encrypt_data(filename, salt, key, dataset_directory, dirname, iv, dataset_sas_uri, n, count)

    print(f'Dataset successfully encrypted and uploaded to SAS URL {dataset_sas_uri}.')


def encrypt_upload_dataset_from_blob(dataset_sas_uri_unencrypted: str, content_encryption_key: str, dataset_sas_uri: str):
    '''
    Encrypt and upload a Dataset to Azure Blob Storage. Dataset encryption safeguards your dataset during storage, 
    transmission, and execution. The dataset is encrypted using a Content Encryption Key (CEK) and uploaded using
    a Shared Access Signature (SAS) URL.
    '''

    with open(content_encryption_key, 'rb') as file:
        cek = file.read()
    
    salt = os.urandom(8)
    pbkdf2_hash = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32 + 12,
        iterations=10000,
        backend=default_backend()
    )

    derived_password = pbkdf2_hash.derive(cek)
    key = derived_password[0:32]
    iv = derived_password[32:(32 + 12)]
    
    unencrypted_client = ContainerClient.from_container_url(dataset_sas_uri_unencrypted)
    encrypted_client = ContainerClient.from_container_url(dataset_sas_uri)
    blobs = unencrypted_client.list_blob_names()

    count = 0
    for blob in blobs:
        count += 1
    
    blobs = unencrypted_client.list_blob_names() # reset page

    n = 1
    print(f'{str(count)} blob(s) to be encrypted and uploaded.')
    for blob in blobs:
        unencrypted_client = ContainerClient.from_container_url(dataset_sas_uri_unencrypted)
        encrypted_client = ContainerClient.from_container_url(dataset_sas_uri)
        print(f'Beginning download of blob {blob} ({n}/{str(count)})...')
        data = unencrypted_client.download_blob(blob).readall()
        print(f'Encrypting blob {blob}...')
        encrypted = AESGCM(key).encrypt(iv, data, None)
        encrypted = b'Salted__' + salt + encrypted
        print(f'Uploading blob {blob}...')
        encrypted_client.upload_blob(blob + '.bkenc', encrypted, overwrite=True)
        print(f'Blob {blob + '.bkenc'} uploaded ({n}/{str(count)}).')
        n += 1

    print(f'Dataset {dataset_sas_uri_unencrypted} successfully encrypted and uploaded to SAS URL {dataset_sas_uri}.')
