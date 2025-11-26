# BLS Aggregate Signatures

Implementation of a two-party aggregate signature scheme using BLS signatures. This allows multiple signatures on the same message to be combined into a single compact signature.

## Overview

Aggregate signatures reduce the size and verification cost when multiple parties sign the same message. Instead of verifying N individual signatures, you can verify a single aggregated signature against an aggregated public key.

## Limitations

- Currently only supports 2-party aggregation
- All signers must sign the same message

## Use Cases

- Multi-signature wallets
- Consensus mechanisms with multiple validators
- Certificate aggregation
- Reducing bandwidth in distributed systems
- Blockchain transaction batching
