# https://pyfhel.readthedocs.io/en/latest/_autoexamples/index.html

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import base64

# Generate a symmetric key
def generate_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

# Encrypt data with a given key
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext

# Decrypt data with a given key
def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

    return plaintext

# Hierarchical Key Aggregation (HKA) function
def hierarchical_key_aggregation(parent_key: bytes, child_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'Hierarchical Key Aggregation',
        backend=default_backend()
    )
    return hkdf.derive(parent_key + child_key)

# Example Usage
password1 = b'parent_password'
password2 = b'child_password'
salt1 = os.urandom(16)
salt2 = os.urandom(16)

# Generate keys
parent_key = generate_key(password1, salt1)
child_key = generate_key(password2, salt2)

# Perform hierarchical key aggregation
aggregated_key = hierarchical_key_aggregation(parent_key, child_key)

# Encrypt data
plaintext = b'This is a secret message.'
ciphertext = encrypt(plaintext, aggregated_key)
print(f'Ciphertext: {ciphertext}')

# Decrypt data
decrypted_message = decrypt(ciphertext, aggregated_key)
print(f'Decrypted message: {decrypted_message}')
