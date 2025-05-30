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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

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

# === Claves PEM que tú defines manualmente ===
PEM_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCy+TqA8oSWOBOk
BPW1CrsqdV2sOuA5FO6ZBWgAYq5ZNeB+IxQ8gfnFXjg6ZFDT0+ysaJaJ2GPufh7I
8QavSKi30ThOamEA/g2BGgYxVx+hr10k+BptkL4w9ZfruFABS5mhQxzFcQxOjRTl
m/zEhbFlHfwi9M9ygC/9eqpCO6aOUxQCE+L+uvySNdxRLMsZsVvBQThmXKNLQ20X
Nel/5RkgXVGoERUdH4an9Ww5v+UqeDgmAIdlLDhPCsgh3ObblPdIl/DMHu4zmD9E
wEiGB2uau+9kyrAXZgZvRIFp+VrirbShC4lr2qBr5jwNdPv45t3X7z8jLXxNUyMB
VmvnDcoVAgMBAAECggEAMePx4BI6zZlSOE29pLsaE6rl8uXyrVbdcECmjjzz9yBi
tSbYNEnTM6ahK/3c3j/cYO9Cz6hHqyrzL/aoc2JgzeT/ujRDWEB5yTxU75om0i6N
W4nh7BsGOaWstOQLQWEusVqBAbUSxi7j3WHPY4UVP2fNan0t+vAq8JEqNw5jzpZ4
zaynjHzBPTJ9wft8WK3GCu4EDtbKrnEaXO/K/BIqd+lohbKGEmhhKSkTbzLx/bmI
Dr65l4pZQy7OgyzbXY2izSlBd2/kpvYrTzD+haoH8f5UycdagZsdnBycHlM5T/Fv
/m2AgIN8byUW2HXDJT1GP6T4VFbZdEWv9ieDpA/CHQKBgQDWsFBRELzl5H/q9vN+
87bBOdI4XbEIX0jFRMrNidMcqTQRclfAP29u5VmZ0rJTSzJ0XrzKpN9Fl+diryCD
XhagDnt8quddWoqN3t7j77d97/MutJlsIDDHzyd3qdoFxlIc55TebsNGgpq7BkHu
pMBYHtml0DEBXvWk79qaywJj0wKBgQDVaZC25LnO2X2R4/r2wIKvmC2WqNpUoVmU
v/1HJo1udWWyLK9fI2jGDtXFQTL3o0a/qzMyjZpiufCap7L6fIpmmhWFwx2yaRuP
1Q3GhwfPV9MRtXH8lcETTwSqpX5GOhGFmAIN56NFFFW/XQiK8IN2ZORxPkJAu/WK
y00EVRIxdwKBgQDJB0n9zpWDEyawptM0whMT9geh3iFiPI7QoWzhb7gt80adO5tt
mjjG952iCwgONLCnBPr1KdMjwGzbHC9us1CuSUFaaFHDOX/Z/qJpf1Mrat8kkdnD
xJTI1HIZfAN6Os0y4aqlacQSp0Mp818TjlPJcAHPYRYyOW/9JNdm8MdpHwKBgDPb
jAu1NqVZ2hZ6VIBjNR5gFyvV6f/ImVD4+h2w84sUwdpy20Z9/zapYi6lcjIUndtz
SWSOXiaBUkLyXx5Y5vSZmoM/b1bsDYN83PUR2Mb8a1CRS5p59Umw2MxynGWKNLnG
vzELyXO+xjtS6wGAAiHh0FToMQcz5S2NyzAzT9FvAoGAO07wglEticI4+vAg8HD5
/PcZ5elAkYly2K7xwIwK5q/KrG4dCriJeR0q+j9OqAJZrQ6UUXXDw1xtNesP4Dhg
t62MyYJFWO/2ekPN+dfgaWsWaAEgyaC3vlw3JDmmAJXUuBhS43iwr2mjZA83As0j
7qORX1MdkMbe/iR5bwe5T8E=
-----END PRIVATE KEY-----"""

PEM_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsvk6gPKEljgTpAT1tQq7
KnVdrDrgORTumQVoAGKuWTXgfiMUPIH5xV44OmRQ09PsrGiWidhj7n4eyPEGr0io
t9E4TmphAP4NgRoGMVcfoa9dJPgabZC+MPWX67hQAUuZoUMcxXEMTo0U5Zv8xIWx
ZR38IvTPcoAv/XqqQjumjlMUAhPi/rr8kjXcUSzLGbFbwUE4ZlyjS0NtFzXpf+UZ
IF1RqBEVHR+Gp/VsOb/lKng4JgCHZSw4TwrIIdzm25T3SJfwzB7uM5g/RMBIhgdr
mrvvZMqwF2YGb0SBafla4q20oQuJa9qga+Y8DXT7+Obd1+8/Iy18TVMjAVZr5w3K
FQIDAQAB
-----END PUBLIC KEY-----"""

# === Cargar claves desde los strings PEM ===
private_key = serialization.load_pem_private_key(
    PEM_PRIVATE_KEY,
    password=None,
    backend=default_backend()
)

public_key = serialization.load_pem_public_key(
    PEM_PUBLIC_KEY,
    backend=default_backend()
)

# Modelos Pydantic
class RSAEncryptRequest(BaseModel):
    text: str

class RSADecryptRequest(BaseModel):
    encrypted_text: str

# Cifrador RSA
@app.post("/encrypt_rsa")
def encrypt_rsa(data: RSAEncryptRequest):
    encrypted = public_key.encrypt(
        data.text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(encrypted).decode()
    return {"encrypted_text": encrypted_b64}

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


# --- Algoritmo Transposición --- #

# Transfomación de la palabra clave
def get_colum_order(key: str):
    return sorted(range(len(key)), key=lambda k: key[k]) # Ordena las letras de la clave en orden alfabético y retorna los indices

# Cifrar Transposición
def transposition_encrypt(text: str, key: str):
    order = get_colum_order(key)
    num_cols = len(key)
    num_rows = math.ceil(len(text) / num_cols)
    padded_text = text.ljust(num_cols * num_rows, 'X') # Rellena con X los espacios vacios


    # Creamos la matriz
    matrix = [padded_text[i:i+num_cols] for i in range(0, len(padded_text), num_cols)]

    encrypted = ''
    for col_idx in order:
        for row in matrix:
            encrypted += row[col_idx]
    return encrypted

def transposition_decrypt(encrypted_text: str, key: str):
    order = get_colum_order(key)
    num_cols = len(key)
    num_rows = math.ceil(len(encrypted_text) / num_cols)

    col_lenghts = [num_rows] * num_cols
    cols = [''] * num_cols

    index = 0
    for idx in order:
        cols[idx] = encrypted_text[index:index + col_lenghts[idx]]
        index += col_lenghts[idx]

    decrypted = ''
    for i in range(num_rows):
        for j in range(num_cols):
            if i < len(cols[j]):
                decrypted += cols[j][i]
    return decrypted.rstrip('X') # Quita el relleno X

# Modelos Pydantic
class TranspositionEncryptRequest(BaseModel):
    text: str
    key: str

class TranspositionDecryptRequest(BaseModel):
    encrypted_text: str
    key: str


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

@app.post("/encrypt_transposition")
def encrypt_transposition(data: TranspositionEncryptRequest):
    encrypted = transposition_encrypt(data.text, data.key)
    return {"encrypted_text": encrypted}

@app.post("/decrypt_transposition")
def decrypt_transposition(data: TranspositionDecryptRequest):
    decrypted = transposition_decrypt(data.encrypted_text, data.key)
    return {"decrypted_text": decrypted}

