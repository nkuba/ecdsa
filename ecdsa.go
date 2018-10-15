package tecdsa

import (
	"math/big"
)

type Signature struct {
	R, S *big.Int
}

type Point struct {
	X, Y *big.Int
}
