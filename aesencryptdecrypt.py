from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Hardcoded IV and secret key (these should be kept secure)
iv = b'9R6fDx5G+v3IeFVKWbFTnQ=='
secret_key = b'6d3xa2zW8BfiQ/hUd6JnFA=='

def encrypt(plaintext):
    cipher = AES.new(base64.b64decode(secret_key), AES.MODE_CBC, base64.b64decode(iv))
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext):
    cipher = AES.new(base64.b64decode(secret_key), AES.MODE_CBC, base64.b64decode(iv))
    decrypted_data = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted_data.decode('utf-8')

# Example usage
input_text = "siapanamaandahuh"
encrypted_text = encrypt(input_text)
print("Encrypted:", encrypted_text)

decrypted_text = decrypt(encrypted_text)
print("Decrypted:", decrypted_text)
