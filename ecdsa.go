package tecdsa

import (
	"crypto/sha256"
	"math/big"
)

type Signature struct {
	R, S *big.Int
}

type Point struct {
	X, Y *big.Int
}

func hashAndTrim(message []byte, bitLen int) *big.Int {
	hash := sha256.Sum256(message)
	return new(big.Int).SetBytes(hash[:bitLen/8])
}
