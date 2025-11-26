package main

import (
	"fmt"

	sigagg "bls-signature/signature-aggergations"
)

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

	fmt.Println("TestVerifyWrongSignature:")
	wrongSig := Sign(out2.SecretKey, msg)
	if Verifiy(*out.PublicKey, wrongSig, msg) {
		panic("TestVerifyWrongSignature FAILED")
	} else {
		fmt.Println("  PASS")
	}

	fmt.Println("TestMultipleMessages:")
	messages := []string{"message1", "message2", "message3"}
	for i, m := range messages {
		testSig := Sign(out.SecretKey, m)
		if !Verifiy(*out.PublicKey, testSig, m) {
			panic("TestMultipleMessages FAILED: signature " + fmt.Sprint(i) + " invalid")
		}
	}
	fmt.Println("  PASS")

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

	fmt.Println("\nTestAggregateSignatures:")
	keyPair1, err := keyGen()
	if err != nil {
		panic("Failed to generate keypair 1")
	}
	keyPair2, err := keyGen()
	if err != nil {
		panic("Failed to generate keypair 2")
	}

	commonMsg := "aggregate test message"
	sigOne := Sign(keyPair1.SecretKey, commonMsg)
	sigTwo := Sign(keyPair2.SecretKey, commonMsg)

	aggSig, err := sigagg.AggregateSignatures(sigOne, sigTwo, keyPair1.PublicKey, keyPair2.PublicKey)
	if err != nil {
		panic("TestAggregateSignatures FAILED: " + err.Error())
	}
	if aggSig == nil {
		panic("TestAggregateSignatures FAILED: aggregate signature is nil")
	}

	if !sigagg.AggergateVerifiy(keyPair1.PublicKey, keyPair2.PublicKey, aggSig, []byte(commonMsg)) {
		panic("TestAggregateSignatures FAILED: verification failed")
	}
	fmt.Println("  PASS")

	fmt.Println("\nTestAggregateWrongMessage:")
	wrongMsg := "wrong aggregate message"
	if sigagg.AggergateVerifiy(keyPair1.PublicKey, keyPair2.PublicKey, aggSig, []byte(wrongMsg)) {
		panic("TestAggregateWrongMessage FAILED: wrong message accepted")
	}
	fmt.Println("  PASS")

	fmt.Println("\nTestAggregateSwappedKeys:")
	if sigagg.AggergateVerifiy(keyPair2.PublicKey, keyPair1.PublicKey, aggSig, []byte(commonMsg)) {
		panic("TestAggregateSwappedKeys FAILED: swapped keys accepted")
	}
	fmt.Println("  PASS")

	fmt.Println("\nTestMultipleAggregations:")
	keyPair3, _ := keyGen()
	keyPair4, _ := keyGen()
	sharedMsg := "shared message for aggregation"
	sig3 := Sign(keyPair3.SecretKey, sharedMsg)
	sig4 := Sign(keyPair4.SecretKey, sharedMsg)

	aggSig2, err := sigagg.AggregateSignatures(sig3, sig4, keyPair3.PublicKey, keyPair4.PublicKey)
	if err != nil {
		panic("TestMultipleAggregations FAILED: " + err.Error())
	}

	if !sigagg.AggergateVerifiy(keyPair1.PublicKey, keyPair2.PublicKey, aggSig, []byte(commonMsg)) {
		panic("TestMultipleAggregations FAILED: first aggregation invalid")
	}
	if !sigagg.AggergateVerifiy(keyPair3.PublicKey, keyPair4.PublicKey, aggSig2, []byte(sharedMsg)) {
		panic("TestMultipleAggregations FAILED: second aggregation invalid")
	}
	fmt.Println("  PASS")

	fmt.Println("\nAll tests PASSED")
}
