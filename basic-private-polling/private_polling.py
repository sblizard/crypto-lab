# internal

# external

# built-in
from typing import Tuple


def keyGen() -> Tuple[int, int]:
    """Generate a keypair (pk, sk)"""
    return 0, 0


def encrypt(pk: int, m: int) -> tuple[int, int, int]:
    """Encrypt message m under public key pk, return ciphertext (c1, c2, r)."""
    return 0, 0, 0


def decrypt(sk: int, c_sum: tuple[int, int]) -> int:
    return 0


def generate_proof(pk: int, c: tuple[int, int], m: int, r: int) -> dict:
    """Generate Chaum-Pedersen proof that ciphertext encrypts 0 or 1."""
    return {}
