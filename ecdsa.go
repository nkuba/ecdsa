package tecdsa

import (
	"crypto/sha256"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/golang/go/src/crypto/rand"
)

type Signature struct {
	R, S *big.Int
}

type Point struct {
	X, Y *big.Int
}

func Sign(curve *secp256k1.BitCurve, privateKey *big.Int, message []byte) (*Signature, error) {
	z := hashAndTrim(message, curve.BitSize)

	var k, r, s *big.Int
	for {
		for {
			for {
				var err error
				k, err = rand.Int(rand.Reader, curve.N)
				if err != nil {
					return nil, err
				}
				if k.Sign() > 0 {
					break
				}
			}

			Xp, _ := curve.ScalarBaseMult(k.Bytes())

			r = new(big.Int).Mod(Xp, curve.N)
			if r.Sign() != 0 {
				break
			}
		}
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).ModInverse(k, curve.N),
				new(big.Int).Add(
					z,
					new(big.Int).Mul(r, privateKey),
				),
			),
			curve.N,
		)
		if s.Sign() != 0 {
			break
		}
	}

	return &Signature{R: r, S: s}, nil
}

func hashAndTrim(message []byte, bitLen int) *big.Int {
	hash := sha256.Sum256(message)
	return new(big.Int).SetBytes(hash[:bitLen/8])
}
