package experiments

import (
	"fmt"
	"math/big"
	"time"

	"github.com/jiajunxin/rsa_accumulator/accumulator"
)

// TestFirstLayerPercentage tests the first layer of divide-and-conquer
func TestFirstLayerPercentage() {
	setSize := 10000
	set := accumulator.GenBenchSet(setSize)
	setup := *accumulator.TrustedSetup()
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	startingTime := time.Now().UTC()
	accumulator.ProveMembershipParallel(setup.G, setup.N, rep, 2)
	endingTime := time.Now().UTC()
	var duration = endingTime.Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallel Takes [%.3f] Seconds \n",
		duration.Seconds())
}

// TestMembership tests the running time to generate a membership proof without precomputation
func TestMembership() {
	setSize := 1000000
	set := accumulator.GenBenchSet(setSize)
	setup := *accumulator.TrustedSetup()
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	startingTime := time.Now().UTC()
	prod := accumulator.SetProductRecursiveFast(rep)
	endingTime := time.Now().UTC()
	var duration = endingTime.Sub(startingTime)
	fmt.Printf("Running SetProductRecursiveFast Takes [%.3f] Seconds \n",
		duration.Seconds())

	startingTime = time.Now().UTC()
	accumulator.AccumulateNew(setup.G, prod, setup.N)
	//accumulator.ProveMembershipParallel(setup.G, setup.N, rep, 2)
	endingTime = time.Now().UTC()
	duration = endingTime.Sub(startingTime)
	fmt.Printf("Running AccumulateNew Takes [%.3f] Seconds \n",
		duration.Seconds())
}

// TestProduct test different ways to calculate product of a large set
func TestProduct() {
	setSize := 1000000
	set := accumulator.GenBenchSet(setSize)
	var prod big.Int
	//rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	startingTime := time.Now().UTC()
	//prod = *accumulator.SetProduct2(rep)
	endingTime := time.Now().UTC()
	var duration = endingTime.Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallel Takes [%.3f] Seconds \n",
		duration.Seconds())
	fmt.Println("product length is", prod.BitLen())
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	startingTime = time.Now().UTC()
	prod = *accumulator.SetProductRecursive(rep)
	endingTime = time.Now().UTC()
	duration = endingTime.Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallel Takes [%.3f] Seconds \n",
		duration.Seconds())
	fmt.Println("product length is", prod.BitLen())
}

// TestProduct2 test different ways to calculate product of a large set
func TestProduct2() {
	setSize := 1000000
	set := accumulator.GenBenchSet(setSize)
	var prod big.Int
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	startingTime := time.Now().UTC()
	prod = *accumulator.SetProductRecursive(rep)
	endingTime := time.Now().UTC()
	duration := endingTime.Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallel Takes [%.3f] Seconds \n",
		duration.Seconds())
	fmt.Println("product length is", prod.BitLen())
	var temp big.Int
	startingTime = time.Now().UTC()
	for i := 0; i < 100; i++ {
		temp.Div(&prod, rep[0])
	}
	endingTime = time.Now().UTC()
	duration = endingTime.Sub(startingTime)
	fmt.Printf("Divide for 100 times Takes [%.3f] Seconds \n",
		duration.Seconds())
	fmt.Println("product length is", prod.BitLen())
}

// TestProduct3 test different ways to calculate product of a large set
func TestProduct3() {
	setSize := 10000
	set := accumulator.GenBenchSet(setSize)
	var prod big.Int
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	startingTime := time.Now().UTC()
	prod = *accumulator.SetProductRecursiveFast(rep)
	endingTime := time.Now().UTC()
	duration := endingTime.Sub(startingTime)
	fmt.Printf("Running SetProductRecursiveFast Takes [%.3f] Seconds \n",
		duration.Seconds())
	fmt.Println("product length is", prod.BitLen())
	startingTime = time.Now().UTC()
	prod = *accumulator.SetProductRecursive(rep)
	endingTime = time.Now().UTC()
	duration = endingTime.Sub(startingTime)
	fmt.Printf("Running SetProductRecursive Takes [%.3f] Seconds \n",
		duration.Seconds())
	fmt.Println("product length is", prod.BitLen())
}

func genDIMin(size int) []*big.Int {
	ret := make([]*big.Int, size)
	for i := 0; i < size; i++ {
		ret[i] = accumulator.Min1024
	}
	return ret
}

func genDIMax(size int) []*big.Int {
	ret := make([]*big.Int, size)
	var min257 big.Int
	min257.SetInt64(1)
	min257.Lsh(&min257, 256)
	for i := 0; i < size; i++ {
		ret[i] = new(big.Int)
		ret[i].Add(accumulator.Min1024, &min257)
	}
	//fmt.Println("2048 = ", accumulator.Min2048.String())
	// fmt.Println("257 = ", min257.String())
	// fmt.Println("set1[0] = ", ret[0].String())
	return ret
}

// TestRange tests the bit length of product with DI hash.
func TestRange() {
	setSize := 1000000

	var prodUpper, prodLower, difference big.Int

	set1 := genDIMax(setSize)
	set2 := genDIMin(setSize)

	prodUpper = *accumulator.SetProductRecursive(set1)
	prodLower = *accumulator.SetProductRecursive(set2)

	difference.Sub(&prodUpper, &prodLower)
	fmt.Println("Bit Length of the range is:", difference.BitLen())
	//fmt.Println("The range is:", difference.String())
	fmt.Println("Bit Length of the lower is:", prodLower.BitLen())
	//fmt.Println("The Lower is:", prodLower.String())
	fmt.Println("Bit Length of the upper is:", prodUpper.BitLen())
	//fmt.Println("The Upper is:", prodUpper.String())
}
