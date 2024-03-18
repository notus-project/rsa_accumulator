package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/jiajunxin/rsa_accumulator/experiments"
	"github.com/jiajunxin/rsa_accumulator/merkleswap"
	"github.com/jiajunxin/rsa_accumulator/zkmultiswap"
)

const (
	twoTo14 = 16384
	twoTo15 = 32768
	twoTo16 = 65536
	twoTo17 = 131072
	twoTo18 = 262144
	twoTo19 = 524288
)

func testMembershipproof() {
	// test Membership proof Verification and proof size
	experiments.TestMembershipVerify()
	size := 1000
	startingTime := time.Now().UTC()
	proofs := make([]int, size)
	for i := 0; i < size; i++ {
		proofs[i] = 1
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallelWithTableWithRandomizer with single core for an RSA accumulator Takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	tempProof := proofs[0]
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Println("t = ", tempProof)
	fmt.Printf("Online phase to get one membership proof (retrieve it from memory), Takes [%d] Nanoseconds \n", duration.Nanoseconds())
}

func testbasicprocess() {
	experiments.TestPoKE()
	zkmultiswap.TestMultiSwap(10)
	// outputs a Solidity smart
	zkmultiswap.TestMultiSwapAndOutputSmartContract(10)
	err := zkmultiswap.TestMultiSwapAndOutputSmartContract2(10)
	if err != nil {
		panic(err)
	}
}

func singleCoreComponentProfiler(updateRates int) {
	// The code below measures and reports the proportion of execution time consumed by each component of the system when run on a single processor core.
	fmt.Println("TestNotusMultiSwap for ", twoTo14, " users and ", uint32(twoTo14/updateRates), " updates.")
	experiments.TestNotusMultiSwap(uint32(twoTo14), uint32(twoTo14/updateRates))
	fmt.Println("TestNotusMultiSwap for ", twoTo15, " users and ", uint32(twoTo15/updateRates), " updates.")
	experiments.TestNotusMultiSwap(uint32(twoTo15), uint32(twoTo15/updateRates))
	fmt.Println("TestNotusMultiSwap for ", twoTo16, " users and ", uint32(twoTo16/updateRates), " updates.")
	experiments.TestNotusMultiSwap(uint32(twoTo16), uint32(twoTo16/updateRates))
}

func testNotusParallel(updateRates int) {
	fmt.Println("Test Notus With Different Size")
	experiments.TestMultiSwapWithDifferentSize()
	runtime.GC()
	fmt.Println("TestNotusMultiSwap for ", twoTo15, " users and ", uint32(twoTo15/updateRates), " updates in parallel")
	fmt.Println("Assuming 32 group partations for 2^20 user, each group of 2^15 users uses 32 cores, total 1024 cores")
	experiments.TestNotusParallel(uint32(twoTo15), uint32(twoTo15/updateRates))
	experiments.TestRSAMembershipPreComputeDIParallel(32768, 5) //2^15, 32 cores
	experiments.TestRSAMembershipPreComputeDIParallel(65536, 5) //2^16, 32 cores
	runtime.GC()
	fmt.Println("TestNotusMultiSwap for ", twoTo16, " users and ", uint32(twoTo16/updateRates), " updates in parallel")
	fmt.Println("Assuming 16 group partations for 2^20 user, each group of 2^16 users uses 32 cores, total 512 cores")
	experiments.TestNotusParallel(uint32(twoTo16), uint32(twoTo16/updateRates))
	runtime.GC()
	fmt.Println("TestNotusMultiSwap for ", twoTo17, " users and ", uint32(twoTo17/updateRates), " updates in parallel")
	fmt.Println("Assuming 8 group partations for 2^20 user, each group of 2^17 users uses 32 cores, total 256 cores")
	experiments.TestNotusParallel(uint32(twoTo17), uint32(twoTo17/updateRates))
	runtime.GC()
	fmt.Println("TestNotusMultiSwap for ", twoTo18, " users and ", uint32(twoTo18/updateRates), " updates in parallel")
	fmt.Println("Assuming 4 group partations for 2^20 user, each group of 2^18 users uses 32 cores, total 128 cores")
	experiments.TestNotusParallel(uint32(twoTo18), uint32(twoTo18/updateRates))
	runtime.GC()
	fmt.Println("TestNotusMultiSwap for ", twoTo19, " users and ", uint32(twoTo19/updateRates), " updates in parallel")
	fmt.Println("Assuming 2 group partations for 2^20 user, each group of 2^19 users uses 32 cores, total 64 cores")
	experiments.TestNotusParallel(uint32(twoTo19), uint32(twoTo19/updateRates))
	runtime.GC()
}

func main() {
	//updateRates denotes the percentage of updates in the total users, i.e. number of updates = users/updateRates
	updateRates := 64

	var number int
	fmt.Println("This code is used to benchmark the design of Notus: Dynamic Proofs of Liabilities from Zero-knowledge RSA Accumulators")
	fmt.Println("RSA accumulator parameters are generated for TEST PURPOSE")
	fmt.Println("DO NOT directly use in production")
	fmt.Println("Enter an integer to indicate which experiment you want to run")
	fmt.Println("Note that all SNARK circuit are output to file for reuse. You can keep all of them, or delete all of them, do not delete partically.")
	fmt.Println("Enter 1 to run the basic process, including PoKE protocol, MultiSwap with 10 elements and a smart contract to verify MultiSwap")
	fmt.Println("Enter 2 to run the basic process of RSA accumulator, focusing on membership proof verification")
	fmt.Println("Enter 3 to test proportion of execution time consumed by each component of the system in single thread. This experiment takes a very long time!")
	fmt.Println("Enter 4 to test Membership precomputation under different group size in single thread. This experiment takes a very long time and large memory for precomputation table")
	fmt.Println("Enter 5 to test Notus under different group size in parallel. This experiment takes a very long time and very large memory and disk space.")
	fmt.Println("Make sure you have 32 cores to get correct result.")
	fmt.Println("Enter 6 to simulate the cost of a Merkle Swap with depth 28")
	fmt.Println("Enter 9 to run all above experiments")
	fmt.Println("Enter anything else to exit.")
	_, err := fmt.Scan(&number)
	if err != nil {
		fmt.Println("Error reading integer:", err)
		return
	}

	switch {
	case number == 1:
		fmt.Println("Test basic process of PoKE, MultiSwap and Smart contract generation")
		startingTime := time.Now().UTC()
		testbasicprocess()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running basic process of PoKE, MultiSwap and Smart contract experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	case number == 2:
		fmt.Println("Test basic process of RSA accumulator, focusing on membership proof verification")
		startingTime := time.Now().UTC()
		testMembershipproof()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running  basic process of RSA accumulator experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	case number == 3:
		fmt.Println("Test Single Core Component Profiler")
		startingTime := time.Now().UTC()
		singleCoreComponentProfiler(updateRates)
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Single Core Component Profiler experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	case number == 4:
		fmt.Println("Test Membership precomputation in under different group size")
		startingTime := time.Now().UTC()
		experiments.TestDifferentMembershipForDISingleThread()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Membership precomputation experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	case number == 5:
		fmt.Println("Test Notus under different group size in parallel")
		startingTime := time.Now().UTC()
		testNotusParallel(updateRates)
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Notus experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	case number == 6:
		startingTime := time.Now().UTC()
		fmt.Println("Test to simulate the cost of a Merkle Swap with depth 28")
		merkleswap.TestMerkleMultiSwap(1024)
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Merkle Swap experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	case number == 9:
		fmt.Println("Test basic process of PoKE, MultiSwap and Smart contract generation")
		startingTime := time.Now().UTC()
		testbasicprocess()
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running basic process of PoKE, MultiSwap and Smart contract experiment. Takes [%.3f] Seconds \n", duration.Seconds())
		fmt.Println("Test basic process of RSA accumulator, focusing on membership proof verification")
		startingTime = time.Now().UTC()
		testMembershipproof()
		duration = time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running basic process of RSA accumulator experiment. Takes [%.3f] Seconds \n", duration.Seconds())
		fmt.Println("Test Single Core Component Profiler")
		startingTime = time.Now().UTC()
		singleCoreComponentProfiler(updateRates)
		duration = time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Single Core Component Profiler experiment. Takes [%.3f] Seconds \n", duration.Seconds())
		fmt.Println("Test Membership precomputation in under different group size")
		startingTime = time.Now().UTC()
		experiments.TestDifferentMembershipForDISingleThread()
		duration = time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Membership precomputation experiment. Takes [%.3f] Seconds \n", duration.Seconds())
		fmt.Println("Test Notus under different group size in parallel")
		startingTime = time.Now().UTC()
		testNotusParallel(updateRates)
		duration = time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Notus experiment. Takes [%.3f] Seconds \n", duration.Seconds())
		startingTime = time.Now().UTC()
		fmt.Println("Test to simulate the cost of a Merkle Swap with depth 28")
		merkleswap.TestMerkleMultiSwap(1024)
		duration = time.Now().UTC().Sub(startingTime)
		fmt.Printf("Running Merkle Swap experiment. Takes [%.3f] Seconds \n", duration.Seconds())
	default:
		return
	}
}
