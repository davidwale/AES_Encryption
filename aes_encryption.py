from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def encrypt(plaintext, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

key = os.urandom(32)  
plaintext = 'Welcome to Lagos'

encrypted = encrypt(plaintext, key)

hex_output = encrypted.hex()
base64_output = base64.b64encode(encrypted).decode()

print(f"Plaintext: {plaintext}")
print(f"Encrypted (HEX): {hex_output}")
print(f"Encrypted (Base64): {base64_output}")

decrypted_hex = decrypt(bytes.fromhex(hex_output), key)
print(f"Decrypted from HEX: {decrypted_hex}")

decrypted_base64 = decrypt(base64.b64decode(base64_output), key)
print(f"Decrypted from Base64: {decrypted_base64}")