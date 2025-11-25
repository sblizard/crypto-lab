# Private Polling System

A privacy-preserving voting system implementing additively homomorphic EC-ElGamal encryption with Chaum–Pedersen zero-knowledge proofs to ensure ballot validity without revealing individual votes.

Developed as part of a cryptographic polling project exploring homomorphic tallying, validity proofs, and secure vote aggregation.

## Features

- **Elliptic-Curve ElGamal Encryption**  
  Based on curve _secp256r1_, enabling strong public-key confidentiality.

- **Additive Homomorphism**  
  Votes can be securely summed using ciphertext addition, enabling encrypted tallying.

- **Zero-Knowledge Vote Validity Proofs**  
  Chaum–Pedersen proofs ensure each vote is **0 or 1** without revealing which value was cast.

- **Encrypted Vote Submission**  
  Voters generate ciphertexts + ZK proofs locally; the system verifies them before aggregation.

- **Invalid Vote Detection**  
  Any ciphertext with a malformed proof is rejected before inclusion in the tally.

- **Privacy-Preserving Tallying**  
  Only the **final total** is decrypted; individual votes are never revealed.

## Cryptographic Primitives

| Function              | Primitive      | Notes                    |
| --------------------- | -------------- | ------------------------ |
| Public-Key Encryption | EC-ElGamal     | Additively homomorphic   |
| Curve                 | secp256r1      | From `tinyec`            |
| Zero-Knowledge Proof  | Chaum–Pedersen | Proves vote ∈ {0,1}      |
| Hashing               | SHA-256        | Fiat–Shamir challenge    |
| Data Models           | Pydantic       | Structured serialization |

---

## Security Properties

### Ballot Privacy

- ElGamal encryption ensures no one can decrypt individual votes.

### Vote Validity

- Zero-knowledge proofs ensure each ciphertext encrypts either `0` or `1`.
- Invalid or malicious ballots are discarded before tallying.

### Verifiable Tallying

- All proofs are validated before combining ciphertexts.
- Only the final sum is decrypted by the private key holder.

### Homomorphic Aggregation

- Votes remain encrypted throughout the aggregation phase.
- Decryption reveals only the number of “Yes” votes.
