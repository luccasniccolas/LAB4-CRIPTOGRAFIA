from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def format_key(alg, key):
    if alg == "DES":
        max_size = 8
    elif alg == "3DES":
        max_size = 24
    elif alg == "AES":
        max_size = 32
    else:
        return None

    key = key.encode()
    if len(key) > max_size:
        key = key[:max_size]
    elif len(key) < max_size:
        diff = max_size - len(key)
        key += get_random_bytes(diff)

    return key

def format_iv(alg, iv):
    if alg == "DES" or alg == "3DES":
        max_size = 8
    elif alg == "AES":
        max_size = 16
    else:
        return None

    iv = iv.encode()
    if len(iv) > max_size:
        iv = iv[:max_size]
    elif len(iv) < max_size:
        diff = max_size - len(iv)
        iv += get_random_bytes(diff)

    return iv

def aes_encrypt(text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_data = cipher.encrypt(pad(text, AES.block_size))
    return cipher_data

def aes_decrypt(cipher_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(cipher_data), AES.block_size)
    return decrypted_data

def des_encrypt(text, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    cipher_data = cipher.encrypt(pad(text, DES.block_size))
    return cipher_data

def des_decrypt(cipher_data, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(cipher_data), DES.block_size)
    return decrypted_data

def des3_encrypt(text, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    cipher_data = cipher.encrypt(pad(text, DES3.block_size))
    return cipher_data

def des3_decrypt(cipher_data, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(cipher_data), DES3.block_size)
    return decrypted_data

# Ingreso de llaves y vectores de inicialización
des_key = input("Ingrese la llave de DES: ")
des3_key = input("Ingrese la llave de 3DES: ")
aes_key = input("Ingrese la llave de AES: ")

des_iv = input("Ingrese el vector de inicializacion de DES: ")
des3_iv = input("Ingrese el vector de inicializacion de 3DES: ")
aes_iv = input("Ingrese el vector de inicializacion de AES: ")

text_to_cipher = input("Ingrese el texto a cifrar: ").encode()

# Ajuste de llaves y vectores
des_key = format_key("DES", des_key)
des3_key = format_key("3DES", des3_key)
aes_key = format_key("AES", aes_key)

des_iv = format_iv("DES", des_iv)
des3_iv = format_iv("3DES", des3_iv)
aes_iv = format_iv("AES", aes_iv)

print(f"DES: key={des_key.hex()}\tiv={des_iv}")
print(f"3DES: key={des3_key.hex()}\tiv={des3_iv}")
print(f"AES: key={aes_key.hex()}\tiv={aes_iv}")

# Cifrado
des_encrypted = des_encrypt(text_to_cipher, des_key, des_iv)
des3_encrypted = des3_encrypt(text_to_cipher, des3_key, des3_iv)
aes_encrypted = aes_encrypt(text_to_cipher, aes_key, aes_iv)

print(f"DES encrypt: {des_encrypted.hex()}")
print(f"3DES encrypt: {des3_encrypted.hex()}")
print(f"AES encrypt: {aes_encrypted.hex()}")

# Desencriptado
des_decrypted = des_decrypt(des_encrypted, des_key, des_iv).decode()
des3_decrypted = des3_decrypt(des3_encrypted, des3_key, des3_iv).decode()
aes_decrypted = aes_decrypt(aes_encrypted, aes_key, aes_iv).decode()

print(f"DES decrypt: {des_decrypted}")
print(f"3DES decrypt: {des3_decrypted}")
print(f"AES decrypt: {aes_decrypted}")
