# internal
from .types import ChaumPedersenProof, Proof, EncryptedVote, ECCKeyPair

# external
from tinyec import registry


# built-in
from typing import cast
import secrets

CURVE = registry.get_curve("secp256r1")


def keyGen() -> ECCKeyPair:
    """Generate a keypair (pk, sk)"""
    priv_key = secrets.randbelow(CURVE.field.n)
    pub_key_point = priv_key * CURVE.g
    assert (
        pub_key_point.x is not None and pub_key_point.y is not None
    ), "Invalid public key point"
    pub_key = (cast(int, pub_key_point.x), cast(int, pub_key_point.y))
    return ECCKeyPair(public_key=pub_key, private_key=priv_key)


def encrypt(pk: int, m: int) -> tuple[int, int, int]:
    """Encrypt message m under public key pk, return ciphertext (c1, c2, r)."""
    return 0, 0, 0


def decrypt(sk: int, c_sum: tuple[int, int]) -> int:
    return 0


def generate_proof(pk: int, c: tuple[int, int], m: int, r: int) -> ChaumPedersenProof:
    """Generate Chaum-Pedersen proof that ciphertext encrypts 0 or 1."""
    return ChaumPedersenProof(A1=0, A2=0, z=0)


def verify_proof(pk: int, c: tuple[int, int], proof: dict) -> bool:
    """Verify the zero-knowledge proof for a given ciphertext."""
    return False


def submit_vote(pk: int, vote: int) -> EncryptedVote:
    """Return an encrypted vote and proof."""
    return EncryptedVote(
        ciphertext=(0, 0),
        proof=Proof(commitment_a=0, commitment_b=0, challenge=0, response=0),
    )


def tally_votes(sk: int, votes: list[EncryptedVote]) -> int:
    """Aggregate all encrypted votes and decrypt final tally."""
    return 0


def add_ciphertexts(c1: tuple[int, int], c2: tuple[int, int]) -> tuple[int, int]:
    """Return the componentwise product of two ciphertexts."""
    return 0, 0
