from pydantic import BaseModel
from struct import pack, unpack
import math
import mysql.connector
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64


app = FastAPI()
# Middleware CORS para permitir solicitudes desde tu frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://paginaencriptar.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Conexión a MySQL
def get_mysql_connection():
    return mysql.connector.connect(
        host="192.168.100.114",
        user="root",
        password="gabriel2005",
        database="textos_encriptados"
    )


# Parámetros de RC5
w = 32         # tamaño de palabra (bits)
r = 12         # número de rondas
b = 16         # bytes de la clave (128 bits)
mod = 2 ** w   # módulo 2^w, porque trabajamos con palabras de 32 bits
P = 0xB7E15163
Q = 0x9E3779B9
#P y Q se utilizan durante la fase de expansión de clave para generar la tabla de subclaves S,
# que es fundamental para el cifrado y descifrado de los bloques de datos.
SECRET_KEY = "claveSecreta123" #clave simetrica


# === Utilidades RC5 ===
#Este metodo transforma la clave secreta del usuario en un arreglo de subclaves S,
# que se usan durante el cifrado y descifrado.
#Pasos:
#Divide la clave original en palabras de 32 bits → array L.
#Crea un array S de subclaves inicializado con P, y luego suma Q secuencialmente.
#Mezcla S y L en 3 × max(len(S), len(L)) iteraciones, usando rotaciones y sumas.
#Esta fase se llama expansión de clave.

def rc5_key_schedule(key: bytes):
    u = w // 8
    c = max(1, math.ceil(len(key) / u))
    L = [0] * c
    for i in range(len(key) - 1, -1, -1):
        L[i // u] = (L[i // u] << 8) + key[i]

    t = 2 * (r + 1)
    S = [0] * t
    S[0] = P
    for i in range(1, t):
        S[i] = (S[i - 1] + Q) % mod

    i = j = A = B = 0
    for _ in range(3 * max(t, c)):
        A = S[i] = ((S[i] + A + B) << 3 | (S[i] + A + B) >> (w - 3)) % mod
        B = L[j] = ((L[j] + A + B) << ((A + B) % w) | (L[j] + A + B) >> (w - ((A + B) % w))) % mod
        i = (i + 1) % t
        j = (j + 1) % c

    return S
#Aplica relleno tipo PKCS#7 para que el mensaje tenga longitud múltiplo de 8 bytes (64 bits).
def pad(data: bytes, block_size=8):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data: bytes):
    padding_len = data[-1]
    return data[:-padding_len]

#Recibe un bloque de 64 bits (8 bytes) y las subclaves S. Aplica r rondas de:
#XOR
#Rotaciones circulares (shifts)
#Sumas módulo 2³²
def encrypt_block(block: bytes, S):
    A, B = unpack('<2I', block)
    A = (A + S[0]) % mod
    B = (B + S[1]) % mod
    for i in range(1, r + 1):
        A = ((A ^ B) << (B % w) | (A ^ B) >> (w - (B % w))) % mod
        A = (A + S[2 * i]) % mod
        B = ((B ^ A) << (A % w) | (B ^ A) >> (w - (A % w))) % mod
        B = (B + S[2 * i + 1]) % mod
    return pack('<2I', A, B)

def decrypt_block(block: bytes, S):
    A, B = unpack('<2I', block)
    for i in range(r, 0, -1):
        B = ((B - S[2 * i + 1]) % mod)
        B = ((B >> (A % w) | B << (w - (A % w))) % mod) ^ A
        A = ((A - S[2 * i]) % mod)
        A = ((A >> (B % w) | A << (w - (B % w))) % mod) ^ B
    B = (B - S[1]) % mod
    A = (A - S[0]) % mod
    return pack('<2I', A, B)

#Codifica el texto y la clave.
#Genera subclaves con rc5_key_schedule.
#Divide en bloques de 8 bytes, cifra cada uno, y convierte el resultado a hexadecimal.
def rc5_encrypt(plaintext: str, password: str):
    key = password.encode()
    S = rc5_key_schedule(key)
    padded = pad(plaintext.encode())
    ciphertext = b''
    for i in range(0, len(padded), 8):
        block = padded[i:i + 8]
        ciphertext += encrypt_block(block, S)
    return ciphertext.hex()

def rc5_decrypt(ciphertext_hex: str, password: str):
    key = password.encode()
    S = rc5_key_schedule(key)
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        plaintext += decrypt_block(block, S)
    return unpad(plaintext).decode()

# Algoritmo cesar
def cesar_encrypt(text: str, shift: int):
    result = ''
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def cesar_decrypt(text: str, shift: int):
    return cesar_encrypt(text, -shift)

# === Modelos Pydantic ===
class EncryptTextRequest(BaseModel):
    texto: str

class DecryptTextRequest(BaseModel):
    encrypted_text: str

class CesarEncryptRequest(BaseModel):
    text: str
    shift: int

class CesarDecryptRequest(BaseModel):
    encrypted_text: str
    shift: int

# ---- ALgoritmo RSA ---- #

# Generador de Keys RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Modelos Pydantic
class RSAEncryptRequest(BaseModel):
    text: str

class RSADecryptRequest(BaseModel):
    encrypted_text: str

# Cifrador RSA
@app.post("/encrypt_rsa")
def encrypt_rsa(data: RSAEncryptRequest):
    encrypted = public_key.encrypt(
        data.text.encode(), # Aqui se convierte el texto en Bytes, porque RSA no trabaja con cadenas
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(encrypted).decode() # Convierte el resultado de binario a base64 para enviarlo por JSON
    return {"encrypted_text": encrypted_b64}

# Descifrar RSA
@app.post("/decrypt_rsa")
def decrypt_rsa(data: RSADecryptRequest):
    encrypted_bytes = base64.b64decode(data.encrypted_text)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"decrypted_text": decrypted.decode()}


# === Endpoints FastAPI ===
@app.post("/encrypt_rc5")
def encrypt_rc5_text(data: EncryptTextRequest):
    encrypted = rc5_encrypt(data.texto, SECRET_KEY)
    return {"encrypted_text": encrypted}

@app.post("/decrypt_rc5")
def decrypt_rc5_text(data: DecryptTextRequest):
    try:
        decrypted = rc5_decrypt(data.encrypted_text, SECRET_KEY)
        return {"decrypted_text": decrypted}
    except Exception as e:
        return {"error": str(e)}

@app.post("/encrypt_cesar")
def encrypt_cesar(data: CesarEncryptRequest):
    encrypted = cesar_encrypt(data.text, data.shift)
    return {"encrypted_text": encrypted}

@app.post("/decrypt_cesar")
def decrypt_cesar(data: CesarDecryptRequest):
    decrypted = cesar_decrypt(data.encrypted_text, data.shift)
    return {"decrypted_text": decrypted}

