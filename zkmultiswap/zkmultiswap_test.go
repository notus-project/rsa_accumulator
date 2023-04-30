package zkmultiswap

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bnPoseidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	iden3Poseidon "github.com/iden3/go-iden3-crypto/poseidon"
)

// compare return 0 if input1 == input2
func compare(input1 *big.Int, input2 []byte) int {
	input1bytes := input1.Bytes()
	return bytes.Compare(input1bytes, input2)
}

func elementFromString(v string) *fr.Element {
	n, success := new(big.Int).SetString(v, 10)
	if !success {
		panic("Error parsing hex number")
	}
	var e fr.Element
	e.SetBigInt(n)
	return &e
}

func TestPoseidonHash(t *testing.T) {
	inputs := "3"
	result1, err := iden3Poseidon.HashBytes([]byte(inputs))
	if err != nil {
		panic(err)
	}

	poseidonHasher := bnPoseidon.NewPoseidon()
	poseidonHasher.Write([]byte(inputs))
	result2 := poseidonHasher.Sum(nil)

	result3 := bnPoseidon.Poseidon(elementFromString(inputs))

	if compare(result1, result2) != 0 {
		fmt.Println("result1 = ", result1.String())
		fmt.Println("result2 = ", result2)
		fmt.Println("result3 = ", result3)
		t.Errorf("proofs generated are not consistent")
	}

}
