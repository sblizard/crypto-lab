package main

import blst "github.com/supranational/blst/bindings/go"

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

type KeyGenOutput struct {
	SecretKey *blst.SecretKey
	PublicKey *blst.P1Affine
}
