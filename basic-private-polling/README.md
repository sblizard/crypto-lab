# Private Polling System

A secure electronic voting system implementing homomorphic encryption and zero-knowledge proofs for privacy-preserving elections.

---

## Features

- **Voter Privacy**: Votes are encrypted and never revealed individually
- **Homomorphic Tallying**: Votes can be summed without decryption
- **Zero-Knowledge Proofs**: Each vote proves it's valid (0 or 1) without revealing the choice
- **Public Verifiability**: Anyone can verify votes are valid using the zero-knowledge proofs
- **Chaum-Pedersen Protocol**: Efficient proof system for vote validity
- **Elliptic Curve Cryptography**: Based on secp256r1 curve for efficient computation

---

## Architecture

The implementation consists of cryptographic primitives for secure voting:

### **Core Functions**

#### Vote Management:

- `keyGen()` - Generates election keypair (public/private)
- `submit_vote(pk, vote)` - Encrypts a vote and generates a validity proof
- `tally_votes(pk, sk, votes)` - Aggregates and decrypts final tally

#### Encryption Primitives:

- `encrypt(pk, m)` - Encrypts a message under the public key
- `decrypt(sk, c_sum, num_votes)` - Decrypts the summed ciphertext via brute force
- `add_two_ciphertexts(c1, c2)` - Homomorphically adds two encrypted votes

#### Zero-Knowledge Proofs:

- `generate_proof(pk, ct, m)` - Creates a Chaum-Pedersen proof that ct encrypts 0 or 1
- `verify_proof(pk, ct, proof)` - Verifies a vote's validity without learning the vote

---

## Cryptographic Primitives

| Function                 | Primitive               | Notes                                               |
| ------------------------ | ----------------------- | --------------------------------------------------- |
| **Encryption Scheme**    | Exponential ElGamal     | Homomorphic over addition                           |
| **Curve**                | secp256r1 (NIST P-256)  | 256-bit elliptic curve                              |
| **Zero-Knowledge Proof** | Chaum-Pedersen Protocol | Proves ciphertext encrypts 0 or 1                   |
| **Hash Function**        | SHA-256                 | Used for Fiat-Shamir transform in proofs            |
| **Decryption**           | Brute Force             | Discrete log solved by checking all possible values |

---

## Requirements

- **Python 3.12+**
- **cryptography** library
- **tinyec** library for elliptic curve operations
- **pydantic** for data validation

Install dependencies:

```bash
pip install cryptography tinyec pydantic
```

---

## How It Works

### 1. Election Setup

The election authority generates a keypair:

```python
keypair = keyGen()
pk = keypair.public_key  # Published to all voters
sk = keypair.private_key  # Kept secret for tallying
```

### 2. Voting

Each voter encrypts their vote (0 or 1) and generates a proof:

```python
encrypted_vote = submit_vote(pk=pk, vote=1)  # Vote "Yes"
```

The encrypted vote contains:

- **Ciphertext**: The encrypted vote (c1, c2)
- **Proof**: A zero-knowledge proof that the vote is 0 or 1

### 3. Verification

Anyone can verify that a vote is valid without learning the vote:

```python
is_valid = verify_proof(pk=pk, ct=encrypted_vote.ciphertext, proof=encrypted_vote.proof)
```

### 4. Tallying

The election authority aggregates all encrypted votes and decrypts the total:

```python
votes = [vote1, vote2, vote3, ...]
tally = tally_votes(pk=pk, sk=sk, votes=votes)
```

If any proof fails verification, `tally_votes` returns `False`.

---

## Security Properties

### **Privacy**

- Individual votes are never revealed during the election
- Only the final tally is decrypted, preserving voter anonymity
- Exponential ElGamal provides semantic security under the DDH assumption

---

### **Integrity**

- Zero-knowledge proofs ensure each vote is either 0 or 1
- Invalid votes are rejected during tallying
- Homomorphic property prevents tampering during aggregation

---

### **Verifiability**

- Anyone can verify that all submitted votes are valid
- Chaum-Pedersen proofs are publicly verifiable
- No trusted setup required beyond the election authority's keypair

---

### **Limitations**

- **Small Tallies Only**: Decryption uses brute force, so only works for reasonably small elections
- **No Receipt-Freeness**: Voters can prove how they voted (by revealing randomness)
- **No Coercion-Resistance**: System cannot prevent forced voting under duress
- **Single Authority**: Election authority can decrypt results (threshold schemes would mitigate this)

---

## Implementation Details

### Exponential ElGamal Encryption

For public key `pk = sk * G` and message `m`:

- Encryption: `(c1, c2) = (r*G, m*G + r*pk)` for random `r`
- Decryption: `M = c2 - sk*c1`, then solve for `m` such that `M = m*G`

The homomorphic property: `Enc(m1) + Enc(m2) = Enc(m1 + m2)`

### Chaum-Pedersen Zero-Knowledge Proof

Proves knowledge of `r` such that `c1 = r*G` and `c2 - m*G = r*pk` for `m ∈ {0, 1}`:

1. Prover chooses random `w` and computes:

   - `A1 = w*G`
   - `A2 = w*pk`

2. Challenge: `c = H(c1, c2, A1, A2)` (Fiat-Shamir)

3. Response: `z = w + c*r`

4. Verifier checks:
   - `z*G = A1 + c*c1`
   - `z*pk = A2 + c*(c2 - m*G)` for `m = 0` or `m = 1`
