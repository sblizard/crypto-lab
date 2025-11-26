# BLS Signatures

Implementation of BLS (Boneh-Lynn-Shacham) signatures using the BLS12-381 curve via the [blst](https://github.com/supranational/blst) library.

## Overview

BLS signatures are short signatures based on bilinear pairings that enable efficient signature aggregation. This implementation provides basic BLS signature operations and an aggregate signature scheme.

## Sections

- [Signature Aggergation](/BLS-signature/signature-aggergations/)

## Use Cases

BLS signatures are particularly useful for:

- Blockchain consensus mechanisms (e.g., Ethereum 2.0)
- Multi-signature schemes
- Threshold signatures
- Compact certificate aggregation
- Any scenario requiring signature aggregation
