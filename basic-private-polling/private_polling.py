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

    if m == 0:
        A1_0: Point = cast(Point, w * CURVE.g)
        A2_0: Point = cast(Point, w * pk)

        c1 = secrets.randbelow(CURVE.field.n)
        z1 = secrets.randbelow(CURVE.field.n)
        A1_1 = cast(Point, z1 * CURVE.g - c1 * U)
        A2_1 = cast(Point, z1 * pk - c1 * cast(Point, (V - CURVE.g)))

        c = hash_points(U, V, A1_0, A2_0, A1_1, A2_1)
        c0 = (c - c1) % CURVE.field.n
        z0 = (w + c0 * r) % CURVE.field.n

        return ChaumPedersenProof(
            A1_0=A1_0, A2_0=A2_0, A1_1=A1_1, A2_1=A2_1, c0=c0, c1=c1, z0=z0, z1=z1
        )

    else:
        A1_1 = cast(Point, w * CURVE.g)
        A2_1 = cast(Point, w * pk)

        c0 = secrets.randbelow(CURVE.field.n)
        z0 = secrets.randbelow(CURVE.field.n)
        A1_0 = cast(Point, z0 * CURVE.g - c0 * U)
        A2_0 = cast(Point, z0 * pk - c0 * V)

        c = hash_points(U, V, A1_0, A2_0, A1_1, A2_1)
        c1 = (c - c0) % CURVE.field.n
        z1 = (w + c1 * r) % CURVE.field.n

        return ChaumPedersenProof(
            A1_0=A1_0, A2_0=A2_0, A1_1=A1_1, A2_1=A2_1, c0=c0, c1=c1, z0=z0, z1=z1
        )


def verify_proof(pk: Point, ct: Ciphertext, proof: ChaumPedersenProof) -> bool:
    """Verify the OR-composition zero-knowledge proof."""
    U: Point = ct.c1
    V: Point = ct.c2

    # Recompute the combined challenge
    c = hash_points(
        U,
        V,
        cast(Point, proof.A1_0),
        cast(Point, proof.A2_0),
        cast(Point, proof.A1_1),
        cast(Point, proof.A2_1),
    )

    # Verify that challenges sum to correct val
    if (proof.c0 + proof.c1) % CURVE.field.n != c:
        return False

    # Verify proof for m=0:
    # U = r*G, V = r*pk
    left1_0 = cast(Point, proof.z0 * CURVE.g)
    right1_0 = cast(Point, proof.A1_0 + cast(Point, proof.c0 * U))

    left2_0 = cast(Point, proof.z0 * pk)
    right2_0 = cast(Point, proof.A2_0 + cast(Point, proof.c0 * V))

    valid_0 = (left1_0 == right1_0) and (left2_0 == right2_0)

    # Verify proof for m=1:
    # U = r*G, (V - G) = r*pk
    left1_1 = cast(Point, proof.z1 * CURVE.g)
    right1_1 = cast(Point, proof.A1_1 + cast(Point, proof.c1 * U))

    left2_1 = cast(Point, proof.z1 * pk)
    V_minus_G = cast(Point, V - CURVE.g)
    right2_1 = cast(Point, proof.A2_1 + cast(Point, proof.c1 * V_minus_G))

    valid_1 = (left1_1 == right1_1) and (left2_1 == right2_1)

    # Both sub-proofs must verify
    return valid_0 and valid_1


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


def hash_points(
    U: Point, V: Point, A1_0: Point, A2_0: Point, A1_1: Point, A2_1: Point
) -> int:
    """Hash all commitment points to generate the challenge."""
    return (
        int.from_bytes(
            sha256(
                str(
                    (
                        U.x,
                        U.y,
                        V.x,
                        V.y,
                        A1_0.x,
                        A1_0.y,
                        A2_0.x,
                        A2_0.y,
                        A1_1.x,
                        A1_1.y,
                        A2_1.x,
                        A2_1.y,
                    )
                ).encode()
            ).digest(),
            "big",
        )
        % CURVE.field.n
    )
