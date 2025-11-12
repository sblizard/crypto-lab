# internal
from .types import ChaumPedersenProof, Proof, EncryptedVote, ECCKeyPair, Ciphertext

# external
from tinyec import registry
from tinyec.ec import Point

# built-in
from typing import cast
import secrets

CURVE = registry.get_curve("secp256r1")


def keyGen() -> ECCKeyPair:
    """Generate a keypair (pk, sk)"""
    priv_key: int = secrets.randbelow(CURVE.field.n)
    pub_key_point = priv_key * CURVE.g
    assert (
        pub_key_point.x is not None and pub_key_point.y is not None
    ), "Invalid public key point"
    pub_key = (cast(int, pub_key_point.x), cast(int, pub_key_point.y))
    return ECCKeyPair(public_key=pub_key, private_key=priv_key)


def encrypt(pk: int, m: int) -> Ciphertext:
    """Encrypt message m under public key pk, return ciphertext (c1, c2, r)."""
    r = secrets.randbelow(CURVE.field.n)
    u = r * CURVE.g

    u = cast(Point, r * CURVE.g)
    v = cast(Point, (m * CURVE.g) + (r * pk))
    return Ciphertext(c1=Point(CURVE.g, u.x, u.y), c2=Point(CURVE.g, v.x, v.y), r=r)


def decrypt(sk: int, c_sum: Ciphertext, num_votes: int) -> int:
    """Decrypt summed ciphertext to recover final vote tally."""
    U = CURVE.on_curve(c_sum.c1.x, c_sum.c1.y)
    V = CURVE.on_curve(
        c_sum.c2.x,
        c_sum.c2.y,
    )

    M = V + (-(sk * U))

    for m in range(0, num_votes):
        if m * CURVE.g == M:
            return m
    raise ValueError("Message not found in search range")


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
