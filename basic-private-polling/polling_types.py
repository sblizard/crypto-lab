# internal

# external
from pydantic import BaseModel, ConfigDict
from tinyec.ec import Point, Inf  # type: ignore

# built-in


class ECCKeyPair(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    public_key: Inf | Point
    private_key: int


class ChaumPedersenProof(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    A1_0: Inf | Point
    A2_0: Inf | Point

    A1_1: Inf | Point
    A2_1: Inf | Point

    c0: int
    c1: int
    z0: int
    z1: int


class InternalCiphertext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    c1: Point
    c2: Point
    r: int


class Ciphertext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    c1: Point
    c2: Point


class EncryptedVote(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ciphertext: Ciphertext
    proof: ChaumPedersenProof


class CombinedCiphertecxt(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    valid_proof: bool
    combined_ciphertext: Ciphertext
