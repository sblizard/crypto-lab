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

    A1: Inf | Point
    A2: Inf | Point
    z: int


class Ciphertext(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    c1: Point
    c2: Point
    r: int


class EncryptedVote(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    ciphertext: Ciphertext
    proof: ChaumPedersenProof


class CombinedCiphertecxt(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    valid_proof: bool
    combined_ciphertext: Ciphertext
