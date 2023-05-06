package zkmultiswap

import (
	"fmt"
	"math/big"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/jiajunxin/rsa_accumulator/accumulator"
	fiatshamir "github.com/jiajunxin/rsa_accumulator/fiat-shamir"
)

const (
	// BitLength is the bit length of the user ID, balnace and epoch number. It can be 32, 64 or any valid number within the field
	BitLength = 32
	// CurrentEpochNum is used for *test purpose* only. It should be larger than the test set size and all OriginalUpdEpoch
	CurrentEpochNum = 1000000
	// OriginalSum is used for *test purpose* only. It should be larger than 0 and the updated balance should also be positive
	OriginalSum = 10000

	// KeyPathPrefix denotes the path to store the circuit and keys. fileName = KeyPathPrefix + "_" + strconv.FormatInt(int64(size), 10) + different names
	KeyPathPrefix = "zkmultiswap"
)

func ElementFromString(v string) *fr.Element {
	n, success := new(big.Int).SetString(v, 10)
	if !success {
		panic("Error parsing hex number")
	}
	var e fr.Element
	e.SetBigInt(n)
	return &e
}

func ElementFromUint32(v uint32) *fr.Element {
	var e fr.Element
	e.SetInt64(int64(v))
	return &e
}

// Set32 is one set for the prover with uint32 for CurrentEpochNum,
type UpdateSet32 struct {
	ChallengeL1      big.Int
	ChallengeL2      big.Int
	RemainderR1      big.Int
	RemainderR2      big.Int
	Randomizer       big.Int
	CurrentEpochNum  uint32
	OriginalSum      uint32
	UpdatedSum       uint32
	UserID           []uint32
	OriginalBalances []uint32
	OriginalHashes   []big.Int
	OriginalUpdEpoch []uint32
	UpdatedBalances  []uint32
}

func (input *UpdateSet32) IsValid() bool {
	if len(input.UserID) < 2 {
		return false
	}
	if len(input.UserID) != len(input.OriginalBalances) {
		return false
	}
	if len(input.UserID) != len(input.OriginalHashes) {
		return false
	}
	if len(input.UserID) != len(input.OriginalUpdEpoch) {
		return false
	}
	if len(input.UserID) != len(input.UpdatedBalances) {
		return false
	}
	return true
}

func getRandomAcc(setup *accumulator.Setup) *big.Int {
	var ret big.Int
	rand := accumulator.GenRandomizer()
	ret.Exp(setup.G, rand, setup.N)
	return &ret
}

// SetupTranscript should takes in all public information regarding the MultiSwap
func SetupTranscript(setup *accumulator.Setup, accOld, accMid, accNew *big.Int, CurrentEpochNum uint32) *fiatshamir.Transcript {
	transcript := fiatshamir.InitTranscript([]string{setup.G.String(), setup.N.String()})
	transcript.Append(strconv.Itoa(int(CurrentEpochNum)))
	return transcript
}

// GenTestSet generates a set of values for test purpose.
// Todo: change Poseidon Hash to DI hash!
func GenTestSet(setsize uint32, setup *accumulator.Setup) *UpdateSet32 {
	var ret UpdateSet32
	ret.UserID = make([]uint32, setsize)
	ret.OriginalBalances = make([]uint32, setsize)
	ret.OriginalUpdEpoch = make([]uint32, setsize)
	ret.OriginalHashes = make([]big.Int, setsize)
	ret.UpdatedBalances = make([]uint32, setsize)

	ret.CurrentEpochNum = CurrentEpochNum
	for i := uint32(0); i < setsize; i++ {
		j := i*2 + 1      // no special meaning for j, just need some non-repeating positive integers
		ret.UserID[i] = j // we need to arrange user IDs in accending order for checking them efficiently
		ret.OriginalBalances[i] = j
		ret.OriginalUpdEpoch[i] = 10
		ret.OriginalHashes[i].SetInt64(int64(j))
		ret.UpdatedBalances[i] = j
	}
	ret.OriginalSum = OriginalSum
	ret.UpdatedSum = OriginalSum // UpdatedSum can be any valid positive numbers, but we are testing the case UpdatedSum = OriginalSum for simplicity

	// get slice of elements removed and inserted
	removeSet := make([]*big.Int, setsize)
	insertSet := make([]*big.Int, setsize)
	for i := uint32(0); i < setsize; i++ {
		tempposeidonHash1 := poseidon.Poseidon(ElementFromUint32(ret.UserID[i]), ElementFromUint32(ret.OriginalBalances[i]),
			ElementFromUint32(ret.OriginalUpdEpoch[i]), ElementFromString(ret.OriginalHashes[i].String()))
		removeSet[i] = new(big.Int)
		tempposeidonHash1.ToBigIntRegular(removeSet[i])

		tempposeidonHash2 := poseidon.Poseidon(ElementFromUint32(ret.UserID[i]), ElementFromUint32(ret.UpdatedBalances[i]),
			ElementFromUint32(ret.CurrentEpochNum), tempposeidonHash1)
		insertSet[i] = new(big.Int)
		tempposeidonHash2.ToBigIntRegular(insertSet[i])
	}
	prod1 := accumulator.SetProductRecursiveFast(removeSet)
	prod2 := accumulator.SetProductRecursiveFast(insertSet)

	// get accumulators
	accMid := getRandomAcc(setup)
	var accOld, accNew big.Int
	accOld.Exp(accMid, prod1, setup.N)
	accNew.Exp(accMid, prod2, setup.N)

	// get challenge
	transcript := SetupTranscript(setup, &accOld, accMid, &accNew, ret.CurrentEpochNum)

	challengeL1 := transcript.GetChallengeAndAppendTranscript()
	challengeL2 := transcript.GetChallengeAndAppendTranscript()

	// get remainder
	remainderR1 := big.NewInt(1)
	remainderR2 := big.NewInt(1)
	remainderR1.Mod(prod1, challengeL1)
	remainderR2.Mod(prod2, challengeL2)

	ret.ChallengeL1 = *challengeL1
	ret.ChallengeL2 = *challengeL2
	ret.RemainderR1 = *remainderR1
	ret.RemainderR2 = *remainderR2
	// Randomizer to be fixed!
	ret.Randomizer = *big.NewInt(200)

	if !ret.IsValid() {
		panic("error in GenTestSet, the generated test set is invalid")
	}
	return &ret
}

// TestMultiSwap is temporarily used for test purpose
func TestMultiSwap() {
	fmt.Println("Start TestMultiSwap")
	testSetSize := uint32(100)
	SetupZkMultiswap(testSetSize)
	testSet := GenTestSet(testSetSize, accumulator.TrustedSetup())

	proof, publicWitness, err := Prove(testSet)
	if err != nil {
		panic(err)
	}

	flag := Verify(proof, testSetSize, publicWitness)
	if flag {
		fmt.Println("Verification passed")
	}
	fmt.Println("Verification failed")
}
