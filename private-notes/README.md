# PrivNotes — Encrypted Note Storage System

A secure encrypted note storage system implementing password-based key derivation and authenticated encryption.  
Developed as part of my personal **Crypto Lab** for exploring practical cryptographic design patterns.

---

## Features

- **Password-Derived Keys:** Uses PBKDF2-HMAC-SHA256 with 2,000,000 iterations for password hardening
- **Authenticated Encryption:** AES-GCM provides both confidentiality and integrity
- **Deterministic Nonces:** Nonce values derived via HMAC to ensure uniqueness and replay protection
- **Rollback Protection:** Optional checksum verification prevents tampering or data rollback
- **Title-Based Keying:** Each note is bound to its title through an HMAC-derived key
- **Fixed-Length Padding:** All notes padded to a constant length to resist length analysis attacks

---

## Architecture

The implementation revolves around a single main component:

### **PrivNotes**

Handles secure creation, storage, and retrieval of encrypted notes.

#### Core Responsibilities:

- Derives master keys from a user-supplied password using PBKDF2
- Uses HMAC-based key derivation to isolate key usage domains (title, encryption, nonce)
- Encrypts notes under AES-GCM with per-note nonces derived from titles and counters
- Provides serialization/deserialization through integrity-checked pickled data

---

## Cryptographic Primitives

| Function                 | Primitive               | Notes                                                |
| ------------------------ | ----------------------- | ---------------------------------------------------- |
| **Key Derivation**       | PBKDF2-HMAC-SHA256      | 2,000,000 iterations, 32-byte key                    |
| **Symmetric Encryption** | AES-GCM                 | 256-bit authenticated encryption                     |
| **MAC / PRF**            | HMAC-SHA256             | Domain-separated key derivation and nonce generation |
| **Integrity Protection** | SHA256                  | Optional checksum verification for rollback defense  |
| **Padding Scheme**       | Fixed 2048-byte padding | Prevents metadata leakage from note lengths          |

---

## Requirements

- **Python 3.12+**
- **cryptography** library (≥ 46.0.2)

Install dependencies:

```bash
pip install cryptography
```

## Security Properties

### **Confidentiality**

- AES-GCM ensures that all notes remain encrypted under a unique per-title key.
- Nonces derived via HMAC prevent reuse even if titles repeat.

---

### **Integrity**

- Authenticated encryption (GCM) prevents note modification or forgery.
- Optional checksum verification guards against rollback or state corruption.

---

### **Password Security**

- PBKDF2 with high iteration count mitigates offline brute-force attacks.
- Salted derivation ensures password uniqueness across instances.

---

### **Metadata Resistance**

- Fixed-size padding ensures all stored ciphertexts have the same length, hiding note size information.
