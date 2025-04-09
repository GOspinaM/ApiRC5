
# 🔐 User Registration API with RC5 Encryption

This is a FastAPI-based web service that allows secure user registration using RC5 encryption. The user credentials (username, email, and password) are encrypted using the RC5 symmetric cipher before being stored in a MongoDB database.

---

## 📦 Features

- Encrypt user passwords using RC5 block cipher before storing
- Decrypt encrypted passwords using the original key
- FastAPI framework for high performance
- MongoDB integration for persistent storage

---

## ⚙️ How It Works

### RC5 Encryption Overview

RC5 is a symmetric block cipher notable for its simplicity and variable parameters:
- **Block size**: 64 bits (2 words of 32 bits)
- **Key size**: Variable (used here: 128 bits)
- **Rounds**: 12 rounds of encryption

RC5 operates in 3 main phases:
1. **Key Expansion**: Converts the input key into a key table.
2. **Encryption**: Processes data block-by-block using XOR, modular addition, and rotations.
3. **Decryption**: Inverses the encryption using the same key.

### Workflow (Activity Diagram Summary)

1. The user sends `username`, `email`, and `password`.
2. Password is encrypted with RC5 using a predefined key (`claveSecreta123`).
3. The encrypted password is stored in MongoDB alongside the user data.
4. When decrypting, the user must provide both the encrypted password and the secret key.

---

## 🔧 API Endpoints

### `POST /encrypt_rc5`

Encrypts the password and returns the encrypted result.

**Request Body:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "mypassword"
}
```

**Response:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "encrypted_password": "ab34cd..."
}
```

---

### `POST /decrypt_rc5`

Decrypts a previously encrypted password using the same secret key.

**Request Body:**
```json
{
  "encrypted_password": "ab34cd...",
  "key": "claveSecreta123"
}
```

**Response:**
```json
{
  "decrypted_password": "mypassword"
}
```

---

## 🛡️ Why RC5?

- Lightweight and fast
- Suitable for environments with constrained resources
- Allows flexibility with key/block/round parameters

Note: RC5 is symmetric, meaning encryption and decryption require the same key. This makes it fast but requires key management.

---

## 📚 Requirements

- Python 3.9+
- FastAPI
- Uvicorn
- Pydantic
- Struct
- (Optional) Motor/MongoDB for DB integration

---

## 🚀 Run the App

```bash
uvicorn main:app --reload
```

Then go to: `http://127.0.0.1:8000/docs` for interactive Swagger UI.

---

## 📂 MongoDB Integration (Optional)

You can store encrypted user data in a MongoDB collection. This example assumes MongoDB is running locally and the credentials are already encrypted using the RC5 logic above.

---
