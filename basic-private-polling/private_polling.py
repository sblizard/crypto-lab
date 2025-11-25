# internal
from polling_types import (
    ChaumPedersenProof,
    EncryptedVote,
    ECCKeyPair,
    Ciphertext,
)

# external
from tinyec import registry  # type: ignore
from tinyec.ec import Point  # type: ignore
from hashlib import sha256

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
    return ECCKeyPair(public_key=pub_key_point, private_key=priv_key)


def encrypt(pk: Point, m: int) -> tuple[Ciphertext, int]:
    """Encrypt message m under public key pk, return ciphertext (c1, c2, r)."""
    r = secrets.randbelow(CURVE.field.n)

    U = cast(Point, r * CURVE.g)
    V = cast(Point, (m * CURVE.g) + (r * pk))

    return Ciphertext(c1=U, c2=V), r


def decrypt(sk: int, c_sum: Ciphertext, num_votes: int) -> int:
    """Decrypt summed ciphertext to recover final vote tally."""
    U: Point = cast(Point, c_sum.c1)
    V: Point = cast(Point, c_sum.c2)

    sk_U: Point = cast(Point, sk * U)
    M: Point = cast(Point, V - sk_U)

    for m in range(num_votes + 1):
        if m * CURVE.g == M:
            return m

    raise ValueError("No matching plaintext found")


def generate_proof(pk: Point, ct: Ciphertext, m: int, r: int) -> ChaumPedersenProof:
    """Generate Chaum-Pedersen proof that ciphertext encrypts 0 or 1."""
    U: Point = ct.c1
    V: Point = ct.c2

    w = secrets.randbelow(CURVE.field.n)

    A1: Point = cast(Point, w * CURVE.g)
    A2: Point = cast(Point, w * pk)

    c: int = (
        int.from_bytes(
            sha256(str((U.x, U.y, V.x, V.y, A1.x, A1.y, A2.x, A2.y)).encode()).digest(),
            "big",
        )
        % CURVE.field.n
    )

    # Proof shows: U = r*G and (V - m*G) = r*pk
    # So z proves knowledge of r in both equations
    z = (w + c * r) % CURVE.field.n

    return ChaumPedersenProof(A1=A1, A2=A2, z=z)


def verify_proof(pk: Point, ct: Ciphertext, proof: ChaumPedersenProof) -> bool:
    """Verify the zero-knowledge proof for a given ciphertext."""
    U: Point = ct.c1
    V: Point = ct.c2

    A1: Point = cast(Point, proof.A1)
    A2: Point = cast(Point, proof.A2)
    z: int = proof.z

    c: int = (
        int.from_bytes(
            sha256(str((U.x, U.y, V.x, V.y, A1.x, A1.y, A2.x, A2.y)).encode()).digest(),
            "big",
        )
        % CURVE.field.n
    )

    # check:
    # g^z == A1 + c * U
    # pk^z == A2 + c * (V - m*G) for m in {0, 1}
    left1: Point = cast(Point, z * CURVE.g)
    right1: Point = cast(Point, A1 + cast(Point, c * U))

    left2: Point = cast(Point, z * pk)

    # Try m = 0
    V_minus_0G: Point = V
    right2_m0: Point = cast(Point, A2 + cast(Point, c * V_minus_0G))

    # Try m = 1
    V_minus_1G: Point = cast(Point, V - CURVE.g)
    right2_m1: Point = cast(Point, A2 + cast(Point, c * V_minus_1G))

    # Proof is valid if equations hold for m=0 or m=1
    valid_m0 = (left1 == right1) and (left2 == right2_m0)
    valid_m1 = (left1 == right1) and (left2 == right2_m1)

    return valid_m0 or valid_m1


def submit_vote(pk: Point, vote: int) -> EncryptedVote:
    """Return an encrypted vote and proof."""
    ct, r = encrypt(pk=pk, m=vote)
    proof: ChaumPedersenProof = generate_proof(pk=pk, ct=ct, m=vote, r=r)

    return EncryptedVote(
        ciphertext=ct,
        proof=proof,
    )


def tally_votes(pk: Point, sk: int, votes: list[EncryptedVote]) -> int | bool:
    """Aggregate all encrypted votes and decrypt final tally."""
    num_votes: int = len(votes)
    if num_votes == 0:
        return 0

    c_sum: Ciphertext | bool = add_ciphertexts(pk=pk, cts=votes)
    if isinstance(c_sum, bool):
        return False

    tally: int = decrypt(sk=sk, c_sum=c_sum, num_votes=num_votes)

    return tally


def add_ciphertexts(pk: Point, cts: list[EncryptedVote]) -> Ciphertext | bool:
    """Aggregate encrypted votes after verifying all proofs."""
    for encrypted_vote in cts:
        if not verify_proof(
            pk=pk, ct=encrypted_vote.ciphertext, proof=encrypted_vote.proof
        ):
            return False

    num_ciphertexts: int = len(cts)
    if num_ciphertexts == 0:
        raise ValueError("Cannot add empty list of ciphertexts")

    if num_ciphertexts == 1:
        return cts[0].ciphertext

    combined_ct: Ciphertext = cts[0].ciphertext

    for i in range(1, num_ciphertexts):
        combined_ct = add_two_ciphertexts(c1=combined_ct, c2=cts[i].ciphertext)

    return combined_ct


def add_two_ciphertexts(c1: Ciphertext, c2: Ciphertext) -> Ciphertext:
    """Return the componentwise product of two ciphertexts."""
    return Ciphertext(
        c1=cast(Point, c1.c1 + c2.c1),
        c2=cast(Point, c1.c2 + c2.c2),
    )
