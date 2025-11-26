package signatureaggergations

import (
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

var AGG_DST = []byte("AGGREGATE_SIGNATURE_DST")
var DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

func AggregateSignatures(sigA, sigB *blst.P2Affine, pkA, pkB *blst.P1Affine) (*blst.P2Affine, error) {
	t := ComputeHash(pkA, pkB, AGG_DST)

	sigAt := new(blst.P2)
	sigAt.FromAffine(sigA)
	sigAt.MultAssign(t)

	agg := new(blst.P2Aggregate)
	if !agg.Add(sigAt.ToAffine(), true) {
		return nil, errors.New("failed to add sigAt")
	}
	if !agg.Add(sigB, true) {
		return nil, errors.New("failed to add sigB")
	}

	return agg.ToAffine(), nil
}

func AggregateVerify(pkA, pkB *blst.P1Affine, aggSig *blst.P2Affine, msg []byte) bool {
	t := ComputeHash(pkA, pkB, AGG_DST)

	pkAt := new(blst.P1)
	pkAt.FromAffine(pkA)
	pkAt.MultAssign(t)

	pkAgg := new(blst.P1Aggregate)
	if !pkAgg.Add(pkAt.ToAffine(), true) {
		return false
	}
	if !pkAgg.Add(pkB, true) {
		return false
	}
	pkAggAffine := pkAgg.ToAffine()

	return aggSig.Verify(
		true,
		pkAggAffine,
		true,
		msg,
		DST,
	)
}

func ComputeHash(pkA, pkB *blst.P1Affine, dts []byte) *blst.Scalar {
	pkABytes := pkA.Compress()
	pkBBytes := pkB.Compress()

	message := append(pkABytes, pkBBytes...)

	t := blst.HashToScalar(message, dts)

	return t
}
