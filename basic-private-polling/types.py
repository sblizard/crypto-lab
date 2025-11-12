# internal

# external
from pydantic import BaseModel

# built-in


class ECCKeyPair(BaseModel):
    public_key: tuple[int, int]
    private_key: int


class Proof(BaseModel):
    commitment_a: int
    commitment_b: int
    challenge: int
    response: int


class EncryptedVote(BaseModel):
    ciphertext: tuple[int, int]
    proof: Proof


class ChaumPedersenProof(BaseModel):
    A1: int
    A2: int
    z: int
