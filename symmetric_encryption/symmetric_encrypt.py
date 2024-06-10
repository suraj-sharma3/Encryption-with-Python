# Symmetric Key Encryption : It only requires a single key for both encryption and decryption.
# Cryptography includes both high level recipes and low level interfaces to common cryptographic algorithms such as symmetric ciphers, etc. 

from cryptography.fernet import Fernet

# Generating Encryption Key

""" 
key = Fernet.generate_key() # Fernet is used to implement symmetric encryption

with open('./symmetric_encryption/generated_key.key', 'wb') as generated_key:
    generated_key.write(key) """

# Loading and Using an Encryption Key

# Loading the key


with open('./symmetric_encryption/generated_key.key', 'rb') as generated_key:
    key = generated_key.read()

# print(key)


# Creating a Fernet object with our key

""" 
fer = Fernet(key)

with open('./symmetric_encryption/user_details.csv', 'rb') as original_file:
    original_data = original_file.read()

# Encrypting the file

encrypted_data = fer.encrypt(original_data)

with open('./symmetric_encryption/enc_user_details.csv', 'wb') as encrypted_file:
    encrypted_file.write(encrypted_data) """

# Decrypting the file

f = Fernet(key)

with open('./symmetric_encryption/enc_user_details.csv', 'rb') as encrypted_file:
    encrypted = encrypted_file.read()

decrypted = f.decrypt(encrypted)

# print(decrypted)

with open('./symmetric_encryption/dec_user_details.csv', 'wb') as decrypted_file:
    decrypted_file.write(decrypted)

