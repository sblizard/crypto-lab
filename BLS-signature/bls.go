package main

import (
	"crypto/rand"

	blst "github.com/supranational/blst/bindings/go"
)

func keyGen() (*KeyGenOutput, error) {
	ikm := make([]byte, 32)
	if _, err := rand.Read(ikm); err != nil {
		return nil, err
	}

	sk := blst.KeyGen(ikm)
	pk := new(blst.P1Affine).From(sk)

	return &KeyGenOutput{
		SecretKey: sk,
		PublicKey: pk,
	}, nil
}

func Sign(sk *blst.SecretKey, m string) *blst.P2Affine {
	dts := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	sig := new(blst.P2Affine).Sign(sk, []byte(m), dts)

	return sig
}

func Verifiy(pk PublicKey, sig *blst.P2Affine, m string) bool {
	dst := []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

	return sig.Verify(true, &pk, true, []byte(m), dst)
}
