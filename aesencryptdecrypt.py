from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Hardcoded IV and secret key (these should be kept secure)
iv = b'0123456789abcdef'
secret_key = b'0123456789abcdef'

def encrypt(plaintext):
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt(ciphertext):
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(base64.b64decode(ciphertext)), AES.block_size)
    return decrypted_data.decode('utf-8')

# Example usage
input_text = "uname=arkaan&password=encrypt"
encrypted_text = encrypt(input_text)
print("Encrypted:", encrypted_text)

decrypted_text = decrypt(encrypted_text)
print("Decrypted:", decrypted_text)
