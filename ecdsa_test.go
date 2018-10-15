package tecdsa

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func TestSignAndVerify(t *testing.T) {
	privateKey := big.NewInt(856)
	curve := secp256k1.S256()

	publicKeyX, publicKeyY := curve.ScalarBaseMult(privateKey.Bytes())
	publicKey := &Point{X: publicKeyX, Y: publicKeyY}

	message := []byte("secret message to sign")
	signature, err := Sign(curve, privateKey, message)
	if err != nil {
		t.Fatal(err)
	}

	result := Verify(curve, signature, publicKey, message)

	if !result {
		t.Fatalf("Signature validation failed")
	}
}
