package main

import "fmt"

func main() {
	fmt.Println("Running BLS demo test suite...")

	fmt.Println("TestKeyGen:")
	out, err := keyGen()
	if err != nil || out.SecretKey == nil || out.PublicKey == nil {
		panic("TestKeyGen FAILED")
	} else {
		fmt.Println("  PASS")
	}

	fmt.Println("TestSign:")
	msg := "hello"
	sig := Sign(out.SecretKey, msg)
	if sig == nil {
		panic("TestSign FAILED")
	} else {
		fmt.Println("  PASS")
	}

	fmt.Println("TestVerifyValid:")
	if !Verifiy(*out.PublicKey, sig, msg) {
		panic("TestVerifyValid FAILED")
	} else {
		fmt.Println("  PASS")
	}

	fmt.Println("TestVerifyWrongMessage:")
	if Verifiy(*out.PublicKey, sig, "wrong message") {
		panic("TestVerifyWrongMessage FAILED")
	} else {
		fmt.Println("  PASS")
	}

	fmt.Println("TestVerifyWrongPublicKey:")
	out2, _ := keyGen()
	if Verifiy(*out2.PublicKey, sig, msg) {
		panic("TestVerifyWrongPublicKey FAILED")
	} else {
		fmt.Println("  PASS")
	}

	fmt.Println("TestFullBLSFlow:")
	msg2 := "integration test"
	sig2 := Sign(out.SecretKey, msg2)

	if !Verifiy(*out.PublicKey, sig2, msg2) {
		panic("TestFullBLSFlow FAILED: correct signature rejected")
	}
	if Verifiy(*out.PublicKey, sig2, "not the same message") {
		panic("TestFullBLSFlow FAILED: wrong message accepted")
	}
	fmt.Println("  PASS")

	fmt.Println("All tests PASSED")
}
