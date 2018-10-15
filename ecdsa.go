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

func Verify(curve *secp256k1.BitCurve, signature *Signature, publicKey *Point, message []byte) bool {
	if signature.R.Cmp(big.NewInt(0)) <= 0 || signature.R.Cmp(curve.N) >= 0 {
		return false
	}

	if signature.S.Cmp(big.NewInt(0)) <= 0 || signature.S.Cmp(curve.N) >= 0 {
		return false
	}

	hash := sha256.Sum256(message)
	z := new(big.Int).SetBytes(hash[:])

	u1 := new(big.Int).Mod(
		new(big.Int).Mul(new(big.Int).ModInverse(signature.S, curve.N), z),
		curve.N,
	)

	u2 := new(big.Int).Mod(
		new(big.Int).Mul(new(big.Int).ModInverse(signature.S, curve.N), signature.R),
		curve.N)

	u1gX, u1gY := curve.ScalarBaseMult(u1.Bytes())
	u2PX, u2Py := curve.ScalarMult(publicKey.X, publicKey.Y, u2.Bytes())
	Px, _ := curve.Add(u1gX, u1gY, u2PX, u2Py)

	if Px.Cmp(signature.R) != 0 {
		return false
	}
	return true
}

func hashAndTrim(message []byte, bitLen int) *big.Int {
	hash := sha256.Sum256(message)
	return new(big.Int).SetBytes(hash[:bitLen/8])
}
