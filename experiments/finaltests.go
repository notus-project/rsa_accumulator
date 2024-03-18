package experiments

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"github.com/jiajunxin/multiexp"
	"github.com/remyoudompheng/bigfft"

	"github.com/jiajunxin/rsa_accumulator/accumulator"
	"github.com/jiajunxin/rsa_accumulator/proof"
	"github.com/jiajunxin/rsa_accumulator/zkmultiswap"
)

// TestMembershipVerify test the time to verify a membership proof
func TestMembershipVerify() {
	setup := *accumulator.TrustedSetup()
	setSize := 10
	set := accumulator.GenBenchSet(setSize)
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	_, proofs := accumulator.AccAndProve(set, accumulator.DIHashFromPoseidon, &setup)
	startingTime := time.Now().UTC()
	repeatNum := 100
	for i := 0; i < repeatNum; i++ {
		// each proof raise to the power of the representative is the process to verify the membership
		_ = accumulator.AccumulateNew(proofs[0], rep[0], setup.N)
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Verifying membership proof for 100 rounds Takes [%.3f] Seconds \n", duration.Seconds())
	fmt.Printf("Verifying membership proof for each one Takes [%.3f] Seconds \n", duration.Seconds()/float64(repeatNum))
	fmt.Println("Proof size = ", proofs[0].BitLen(), "bits")
}

// TestBasicZKrsa test a naive case of zero-knowledge RSA accumulator
func TestBasicZKrsa() {
	setSize := 65536 // 2 ^ 16 65536
	fmt.Println("Test set size = ", setSize)
	fmt.Println("GenRepresentatives with DIHashFromPoseidon")
	set := accumulator.GenBenchSet(setSize)
	setup := *accumulator.TrustedSetup()
	startingTime := time.Now().UTC()
	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	// generate a zero-knowledge RSA accumulator
	r := accumulator.GenRandomizer()
	randomizedBase := accumulator.AccumulateNew(setup.G, r, setup.N)
	// calculate the exponentation
	exp := accumulator.SetProductRecursiveFast(rep)
	accumulator.AccumulateNew(randomizedBase, exp, setup.N)
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generating a zero-knowledge RSA accumulator with set size = %d, takes [%.3f] Seconds \n", setSize, duration.Seconds())

	// Set up
	r, err := rand.Prime(rand.Reader, 10)
	handleErr(err)
	var h, coprime *big.Int
	coprime = new(big.Int)
	big1 := big.NewInt(1)
	for {
		h, err = rand.Int(rand.Reader, setup.N)
		handleErr(err)
		// fmt.Println("N = ", setup.N.String())
		// fmt.Println("h = ", h.String())
		if coprime.GCD(nil, nil, h, setup.N).Cmp(big1) == 0 {
			break
		}
	}
	pp := proof.NewPublicParameters(setup.N, setup.G, setup.H)
	// zkAoP
	prover := proof.NewZKAoPProver(pp, r)
	aop, err := prover.Prove(big.NewInt(100))
	handleErr(err)
	verifier := proof.NewZKAoPVerifier(pp, prover.C)
	if !verifier.Verify(aop) {
		panic("zkAoP verification failed")
	}

	// zkPoKE
	var exponent, C big.Int
	exponent.SetInt64(666)
	C.Exp(setup.G, &exponent, setup.N)
	pokeproof, err := proof.ZKPoKEProve(pp, pp.G, &exponent, &C)
	if err != nil {
		panic("error not empty for TestPoKEStar")
	}
	flag := proof.ZKPoKEVerify(pp, pp.G, &C, pokeproof)
	if !flag {
		panic("did not pass verification")
	}
}

func handleErr(err error) {
	if err != nil {
		panic(err)
	}
}

// TestRSAMembershipPreCompute tests the time to pre-compute all the membership proofs of one RSA accumulator, for different set size, with single core
func TestRSAMembershipPreCompute(setSize int) {
	fmt.Println("Test set size = ", setSize)
	fmt.Println("GenRepresentatives with DIHashFromPoseidon")
	set := accumulator.GenBenchSet(setSize)
	setup := *accumulator.TrustedSetup()

	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	// generate a zero-knowledge RSA accumulator
	r1 := accumulator.GenRandomizer()

	bitLen := 1025
	maxLen := setSize * bitLen / bits.UintSize
	startingTime := time.Now().UTC()
	table := multiexp.NewPrecomputeTable(setup.G, setup.N, maxLen)
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running PreComputeTable Takes [%.3f] Seconds \n", duration.Seconds())

	startingTime = time.Now().UTC()
	proofs1 := accumulator.ProveMembershipParallelWithTableWithRandomizer(setup.G, r1, setup.N, rep[:], 0, table)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallelWithTableWithRandomizer with single core for an RSA accumulator Takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	func() {
		tempProof := proofs1[0]
		_ = tempProof.BitLen() // this line is simply used to allow accessing tempProof
	}()
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Online phase to get one membership proof, Takes [%d] Nanoseconds \n", duration.Nanoseconds())
}

// TestDifferentMembership test the RSAMembershipPreCompute time for different set size.
func TestDifferentMembership() {
	TestRSAMembershipPreCompute(1024)    //2^10
	TestRSAMembershipPreCompute(4096)    //2^12
	TestRSAMembershipPreCompute(16384)   //2^14
	TestRSAMembershipPreCompute(65536)   //2^16
	TestRSAMembershipPreCompute(262144)  //2^18
	TestRSAMembershipPreCompute(1048576) //2^20
}

// TestPoKE tests PoKE's running time.
func TestPoKE() {
	setup := *accumulator.TrustedSetup()
	repeatNum := 2
	fmt.Println("g = ", setup.G.String())
	fmt.Println("N = ", setup.N.String())

	startingTime := time.Now().UTC()
	for i := 0; i < repeatNum; i++ {
		set := accumulator.GenBenchSet(10 + i)
		rep := accumulator.GenRepresentatives(set, accumulator.HashToPrimeFromSha256)
		exp := accumulator.SetProductRecursiveFast(rep)
		accNew := accumulator.AccumulateNew(setup.G, exp, setup.N)
		l := accumulator.HashToPrime(append([]byte(setup.G.String()), []byte(accNew.String())...))
		remainder := big.NewInt(1)
		quotient := big.NewInt(1)
		quotient.DivMod(exp, l, remainder)
		Q := accumulator.AccumulateNew(setup.G, quotient, setup.N)
		AccTest1 := accumulator.AccumulateNew(Q, l, setup.N)
		fmt.Println("Q = ", Q.String())
		fmt.Println("l = ", l.String())
		fmt.Println("Q^l mod N = ", AccTest1.String())
		AccTest2 := accumulator.AccumulateNew(setup.G, remainder, setup.N)
		fmt.Println("r = ", remainder.String())
		fmt.Println("g^r mod N = ", AccTest2.String())
		AccTest3 := AccTest1.Mul(AccTest1, AccTest2)
		AccTest3.Mod(AccTest3, setup.N)
		fmt.Println("Q^l g^r mod N = ", AccTest3.String())
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running PoKE for 100 rounds Takes [%.3f] Seconds \n", duration.Seconds())
}

// TestRSAMembershipPreComputeDIParallel tests the time to pre-compute all the membership proofs of one RSA accumulator, for different set size, with single core
func TestRSAMembershipPreComputeDIParallel(setSize int, limit int) {
	fmt.Println("Test set size = ", setSize)
	fmt.Println("Core limit = 2^", limit)
	fmt.Println("GenRepresentatives with DIHashFromPoseidon")
	set := accumulator.GenBenchSet(setSize)
	setup := *accumulator.TrustedSetup()

	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	// generate a zero-knowledge RSA accumulator
	r1 := accumulator.GenRandomizer()

	maxLen := setSize * 2048 / bits.UintSize
	startingTime := time.Now().UTC()
	table := multiexp.NewPrecomputeTable(setup.G, setup.N, maxLen)
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running PreComputeTable Takes [%.3f] Seconds \n", duration.Seconds())

	startingTime = time.Now().UTC()
	proofs := accumulator.ProveMembershipParallelWithTableWithRandomizer(setup.G, r1, setup.N, rep[:setSize], limit, table)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running ProveMembershipParallelWithTableWithRandomizer for an RSA accumulator Takes [%.3f] Seconds \n", duration.Seconds())
	startingTime = time.Now().UTC()
	func() {
		tempProof := proofs[0]
		_ = tempProof.BitLen() // this line is simply used to allow accessing tempProof
	}()
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Online phase to get one membership proof, Takes [%d] Nanoseconds \n", duration.Nanoseconds())
}

// TestPreComputeTableSize tests the time to pre-compute all the membership proofs of one RSA accumulator, for different set size, with single core
func TestPreComputeTableSize(setSize int) {
	//setSize := 65536 // 2 ^ 16 65536
	fmt.Println("Test set size = ", setSize)
	setup := *accumulator.TrustedSetup()

	maxLen := setSize * 2048 / bits.UintSize
	startingTime := time.Now().UTC()
	table := multiexp.NewPrecomputeTable(setup.G, setup.N, maxLen)
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running PreComputeTable Takes [%.3f] Seconds \n", duration.Seconds())
	fmt.Println("The table size = ", table.TableSize, "rows, ", bits.UintSize, " columns, each element size = ", bits.UintSize)
	fmt.Println("Totally ", table.TableSize*bits.UintSize*bits.UintSize/8, "bytes")
}

// TestDifferentMembershipForDI tests RSAMembershipPreComputeDI in parallel with different set size and number of cores.
// Make sure you have enough cores on your test machine.
func TestDifferentMembershipForDI() {
	TestRSAMembershipPreComputeDIParallel(16384, 0) //2^14, 1 core
	TestRSAMembershipPreComputeDIParallel(16384, 2) //2^14, 4 cores
	TestRSAMembershipPreComputeDIParallel(16384, 4) //2^14, 16 cores

	//TestRSAMembershipPreCompute(16384) //2^14, 1 core

	TestRSAMembershipPreComputeDIParallel(65536, 0) //2^16, 1 core
	TestRSAMembershipPreComputeDIParallel(65536, 2) //2^16, 4 cores
	TestRSAMembershipPreComputeDIParallel(65536, 4) //2^16, 16 cores

	//TestRSAMembershipPreCompute(65536) //2^16, 1 core

	TestRSAMembershipPreComputeDIParallel(262144, 0) //2^18, 1 core
	TestRSAMembershipPreComputeDIParallel(262144, 2) //2^18, 4 cores
	TestRSAMembershipPreComputeDIParallel(262144, 4) //2^18, 16 cores

	//TestRSAMembershipPreCompute(262144) //2^18, 1 core
}

// TestDifferentMembershipForDISingleThread tests the membership pre-computation time under different number of users with single core
func TestDifferentMembershipForDISingleThread() {
	TestRSAMembershipPreCompute(1024)   //2^10, 1 core
	TestRSAMembershipPreCompute(4096)   //2^12, 1 core
	TestRSAMembershipPreCompute(16384)  //2^14, 1 core
	TestRSAMembershipPreCompute(65536)  //2^16, 1 core
	TestRSAMembershipPreCompute(262144) //2^18, 1 core
}

func preComputeDISingleThread(setSize int, table *multiexp.PreTable) {
	set := accumulator.GenBenchSet(setSize)
	setup := *accumulator.TrustedSetup()

	rep := accumulator.GenRepresentatives(set, accumulator.DIHashFromPoseidon)
	// generate a zero-knowledge RSA accumulator
	r1 := accumulator.GenRandomizer()
	accumulator.ProveMembershipSingleThreadWithRandomizer(setup.G, r1, setup.N, rep[:], table)
}

// TestDifferentGroupingSize tests the pre-computation time with different group size.
func TestDifferentGroupingSize(setSize int) {
	max := 262144 //2^18
	setup := *accumulator.TrustedSetup()
	maxLen := setSize * 2048 / bits.UintSize //2048 comes from the length of each DI hash
	//tables := make([]*multiexp.PreTable, 8)
	fmt.Println("TestDifferentGroupingSize, Test set size = ", setSize)
	repeatNum := max / setSize
	fmt.Println("To have same number of users, repeatNum = ", repeatNum)
	table := multiexp.NewPrecomputeTable(setup.G, setup.N, maxLen)
	fmt.Println("Start timer for precomputation of membership proofs")
	startingTime := time.Now().UTC()
	for i := 0; i < repeatNum; i++ {
		preComputeDISingleThread(setSize, table)
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running the trial Takes [%.3f] Seconds \n", duration.Seconds())
}

// TestDifferentGroupSize tests the pre-computation time with different group size.
func TestDifferentGroupSize() {
	TestDifferentGroupingSize(1024)   //2^10
	TestDifferentGroupingSize(4096)   //2^12
	TestDifferentGroupingSize(16384)  //2^14
	TestDifferentGroupingSize(65536)  //2^16
	TestDifferentGroupingSize(262144) //2^18
}

// TestDifferentPrecomputationTableSize tests the running time with different table size.
func TestDifferentPrecomputationTableSize() {
	TestPreComputeTableSize(1024)    //2^10
	TestPreComputeTableSize(4096)    //2^12
	TestPreComputeTableSize(16384)   //2^14
	TestPreComputeTableSize(65536)   //2^16
	TestPreComputeTableSize(262144)  //2^18
	TestPreComputeTableSize(1048576) //2^20
}

// PoKE tests the process of PoKE
func PoKE(base, exp, newAcc, N *big.Int) {
	l := accumulator.HashToPrime(append(newAcc.Bytes(), base.Bytes()...))
	//fmt.Println("primeChallenge = ", l.String())
	remainder := big.NewInt(1)
	quotient := big.NewInt(1)
	quotient.DivMod(exp, l, remainder)
	_ = accumulator.AccumulateNew(base, quotient, N)
	//fmt.Println("Q = ", Q.String())
	//fmt.Println("r = ", remainder.String())
	// AccTest1 := accumulator.AccumulateNew(Q, l, N)
	// fmt.Println("Q^l = ", AccTest1.String())
	// AccTest2 := accumulator.AccumulateNew(base, remainder, N)
	// fmt.Println("g^r = ", AccTest2.String())
	// AccTest3 := AccTest1.Mul(AccTest1, AccTest2)
	// AccTest3.Mod(AccTest3, setup.N)
	// fmt.Println("Accumulator_test3 = ", AccTest3.String()) //AccTest3 should be the same as the AccOld
}

// TestNotusSingleThread tests the process of Notus. RemovedSet is generated to test performance.
// The specific code here is to keep consistant with our SNARK experiments.
// func TestNotusSingleThread(setSize, updatedSetSize int) {
// 	fmt.Println("Test code for Notus system. DO NOT use in production.")
// 	fmt.Println("Random numbers are fixed for test purpose!")
// 	fmt.Println("Test code with Single thread.")
// 	fmt.Println("Test set size = ", setSize)
// 	fmt.Println("Test updated set size = ", updatedSetSize)
// 	currentEpoch := 500
// 	// generate the RemovedSet and insertedSet
// 	removed := make([]*big.Int, updatedSetSize)
// 	insert := make([]*big.Int, updatedSetSize)
// 	if updatedSetSize < 1 {
// 		panic("invalid updatedSetSize")
// 	}
// 	listID := make([]uint32, updatedSetSize)
// 	listValueOriginal := make([]uint32, updatedSetSize)
// 	listValueUpdated := make([]uint32, updatedSetSize)
// 	listLastUpdatedEpoch := make([]uint32, updatedSetSize)
// 	listPrevHash := make([]big.Int, updatedSetSize)
// 	var tempHashInput, tempValLeftShifted big.Int
// 	for i := 0; i < updatedSetSize; i++ {
// 		j := i*2 + 1
// 		listID[i] = uint32(j)
// 		listValueOriginal[i] = uint32(j)
// 		listLastUpdatedEpoch[i] = 10
// 		listPrevHash[i].SetInt64(int64(j))
// 		// input each into Poseidon Hash
// 		tempHashInput.Lsh(big.NewInt(int64(listID[i])), 64)
// 		tempValLeftShifted.Lsh(big.NewInt(int64(listValueOriginal[i])), 32)
// 		tempHashInput.Add(&tempHashInput, &tempValLeftShifted)
// 		tempHashInput.Add(&tempHashInput, big.NewInt(int64(listLastUpdatedEpoch[i])))
// 		removed[i] = accumulator.PoseidonWith2Inputs([]*big.Int{&tempHashInput, &listPrevHash[i]})
// 		listValueUpdated[i] = uint32(j) // the updated value is same as the original value, which is allowed, for the simplicity of testing
// 		tempHashInput.Lsh(big.NewInt(int64(listID[i])), 64)
// 		tempValLeftShifted.Lsh(big.NewInt(int64(listValueUpdated[i])), 32)
// 		tempHashInput.Add(&tempHashInput, &tempValLeftShifted)
// 		tempHashInput.Add(&tempHashInput, big.NewInt(int64(currentEpoch)))
// 		insert[i] = accumulator.PoseidonWith2Inputs([]*big.Int{&tempHashInput, removed[i]})
// 	}
// 	unchangedSet := accumulator.GenBenchSet(setSize - updatedSetSize)
// 	unchanged := accumulator.GenRepresentatives(unchangedSet, accumulator.DIHashFromPoseidon)
// 	// This is for test purpose only.
// 	// We use Hash of tau as the random source, generate 6 different 2048 bits random numbers
// 	// Each 2048 bits random number is composed by 8 256 bits random number, therefore, we
// 	// need 48 256 bits random numbers.
// 	var tau, temp big.Int
// 	tau.SetString("13790045313639893950773977216617751241425918462119445469315488891147110571211", 10)
// 	poseidonHashResult := accumulator.PoseidonWith2Inputs([]*big.Int{&tau, &tau})
// 	tempRandomList := make([]*big.Int, 48)
// 	tempRandomList[0] = poseidonHashResult
// 	for i := 1; i < 48; i++ {
// 		tempRandomList[i] = new(big.Int)
// 		tempRandomList[i] = accumulator.UniversalHashToInt(tempRandomList[i-1])
// 	}
// 	var ranRem1, ranRem2, ranRem3, ranIns1, ranIns2, ranIns3 big.Int
// 	var leftShiftBits uint
// 	for i := 0; i < 8; i++ {
// 		leftShiftBits = 256 * (7 - 1)
// 		temp.Lsh(tempRandomList[i], leftShiftBits)
// 		ranRem1.Add(&ranRem1, &temp)
// 	}
// 	for i := 8; i < 16; i++ {
// 		leftShiftBits = 256 * (15 - 1)
// 		temp.Lsh(tempRandomList[i], leftShiftBits)
// 		ranRem2.Add(&ranRem2, &temp)
// 	}
// 	for i := 16; i < 24; i++ {
// 		leftShiftBits = 256 * (23 - 1)
// 		temp.Lsh(tempRandomList[i], leftShiftBits)
// 		ranRem3.Add(&ranRem3, &temp)
// 	}
// 	for i := 24; i < 32; i++ {
// 		leftShiftBits = 256 * (31 - 1)
// 		temp.Lsh(tempRandomList[i], leftShiftBits)
// 		ranIns1.Add(&ranIns1, &temp)
// 	}
// 	for i := 32; i < 40; i++ {
// 		leftShiftBits = 256 * (39 - 1)
// 		temp.Lsh(tempRandomList[i], leftShiftBits)
// 		ranIns2.Add(&ranIns2, &temp)
// 	}
// 	for i := 40; i < 48; i++ {
// 		leftShiftBits = 256 * (47 - 1)
// 		temp.Lsh(tempRandomList[i], leftShiftBits)
// 		ranIns3.Add(&ranIns3, &temp)
// 	}
// 	original := append(unchanged, removed...)
// 	originalProd := accumulator.SetProductRecursiveFast(original)
// 	originalProd = bigfft.Mul(originalProd, &ranRem1)
// 	setup := *accumulator.TrustedSetup()
// 	maxLen := setSize * 1024 / bits.UintSize
// 	table := multiexp.NewPrecomputeTable(setup.G, setup.N, maxLen)
// 	// generate original zero-knowledge RSA accumulators
// 	accOri := multiexp.ExpParallel(setup.G, originalProd, setup.N, table, 1, 0)
// 	fmt.Println("Precomputation and original RSA accumulators setup. Start to zero-knowledge MultiSwap")
// 	totalTime := time.Now().UTC()
// 	startingTime := time.Now().UTC()
// 	fmt.Println("Generate Acc_mid")
// 	remProd := accumulator.SetProductRecursiveFast(removed)
// 	remProd = bigfft.Mul(remProd, &ranRem1)
// 	var accmidProd1 big.Int
// 	accmidProd1.Div(originalProd, remProd)
// 	accMid := multiexp.ExpParallel(setup.G, originalProd, setup.N, table, 1, 0)
// 	duration := time.Now().UTC().Sub(startingTime)
// 	fmt.Printf("Running Generate Acc_mid Takes [%.3f] Seconds \n", duration.Seconds())
// 	startingTime = time.Now().UTC()
// 	fmt.Println("Generate three zkPoKE")
// 	PoKE(accMid, remProd, accOri, setup.N)
// 	duration = time.Now().UTC().Sub(startingTime)
// 	fmt.Printf("Running Generate three zkPoKE Takes [%.3f] Seconds \n", duration.Seconds())
// 	fmt.Println("Generate Updated accumulators")
// 	startingTime = time.Now().UTC()
// 	insProd := accumulator.SetProductRecursiveFast(insert)
// 	insProd = bigfft.Mul(insProd, &ranIns1)
// 	accUpd1 := accumulator.AccumulateNew(accMid, insProd, setup.N)
// 	duration = time.Now().UTC().Sub(startingTime)
// 	fmt.Printf("Running Generate Updated accumulators Takes [%.3f] Seconds \n", duration.Seconds())
// 	fmt.Println("Generate three zkPoKE")
// 	startingTime = time.Now().UTC()
// 	PoKE(accMid, insProd, accUpd1, setup.N)
// 	duration = time.Now().UTC().Sub(startingTime)
// 	fmt.Printf("Running Generate three zkPoKE Takes [%.3f] Seconds \n", duration.Seconds())
// 	fmt.Println("Generate membership proofs for the three accumulators")
// 	startingTime = time.Now().UTC()
// 	newSet1 := append(unchanged[:], insert...)
// 	proofs1 := accumulator.ProveMembershipParallelWithTableWithRandomizer(setup.G, &ranIns1, setup.N, newSet1[:], 0, table)
// 	duration = time.Now().UTC().Sub(startingTime)
// 	fmt.Printf("Running Generate membership proofs Takes [%.3f] Seconds \n", duration.Seconds())
// 	duration = time.Now().UTC().Sub(totalTime)
// 	fmt.Printf("Running full process Takes [%.3f] Seconds \n", duration.Seconds())
// 	func() {
// 		tempProof := proofs1[0]
// 		_ = tempProof.BitLen()
// 		_ = tempProof.BitLen() // this line is simply used to allow accessing tempProof
// 	}()
// }

// internal function for test purpose only
func isCircuitExist(testSetSize uint32) bool {
	fileName := zkmultiswap.KeyPathPrefix + "_" + strconv.FormatInt(int64(testSetSize), 10) + ".ccs.save"
	_, err := os.Stat(fileName)
	if err == nil {
		return true
	}
	return !os.IsNotExist(err)
}

// TestNotusMultiSwap tests the Notus system and zk-MultiSwap "almost" in single thread
func TestNotusMultiSwap(setsize, updatedSetSize uint32) {
	if !isCircuitExist(updatedSetSize) {
		fmt.Println("Circuit haven't been compiled for testSetSize = ", updatedSetSize, ". Start compiling.")
		startingTime := time.Now().UTC()
		zkmultiswap.SetupZkMultiswap(updatedSetSize)
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Generating a SNARK circuit for set size = %d, takes [%.3f] Seconds \n", updatedSetSize, duration.Seconds())
		runtime.GC()
	} else {
		fmt.Println("Circuit have already been compiled for test purpose.")
	}
	//--------------------------------------------generating accumulator--------------------------------
	var ret zkmultiswap.UpdateSet32
	ret.UserID = make([]uint32, updatedSetSize)
	ret.OriginalBalances = make([]uint32, updatedSetSize)
	ret.OriginalUpdEpoch = make([]uint32, updatedSetSize)
	ret.OriginalHashes = make([]big.Int, updatedSetSize)
	ret.UpdatedBalances = make([]uint32, updatedSetSize)

	ret.CurrentEpochNum = zkmultiswap.CurrentEpochNum
	for i := uint32(0); i < updatedSetSize; i++ {
		j := i*2 + 1      // no special meaning for j, just need some non-repeating positive integers
		ret.UserID[i] = j // we need to arrange user IDs in accending order for checking them efficiently
		ret.OriginalBalances[i] = j
		ret.OriginalUpdEpoch[i] = 10
		ret.OriginalHashes[i].SetInt64(int64(j))
		ret.UpdatedBalances[i] = j
	}
	ret.OriginalSum = zkmultiswap.OriginalSum
	ret.UpdatedSum = zkmultiswap.OriginalSum // UpdatedSum can be any valid positive numbers, but we are testing the case UpdatedSum = OriginalSum for simplicity

	// get slice of elements removed and inserted
	removeSet := make([]*big.Int, updatedSetSize)
	insertSet := make([]*big.Int, updatedSetSize)
	startingTime := time.Now().UTC()
	for i := uint32(0); i < updatedSetSize; i++ {
		var poseidonhash *fr.Element // this is the Poseidon part of the DI hash. We use this to build the hash chain. The original DI hash is to long to directly input into Poseidon hash
		poseidonhash, removeSet[i] = accumulator.PoseidonAndDIHash(accumulator.ElementFromUint32(ret.UserID[i]), accumulator.ElementFromUint32(ret.OriginalBalances[i]),
			accumulator.ElementFromUint32(ret.OriginalUpdEpoch[i]), accumulator.ElementFromString(ret.OriginalHashes[i].String()))
		//fmt.Println("poseidonhash i = ", poseidonhash.String())

		insertSet[i] = accumulator.DIHashPoseidon(accumulator.ElementFromUint32(ret.UserID[i]), accumulator.ElementFromUint32(ret.UpdatedBalances[i]),
			accumulator.ElementFromUint32(ret.CurrentEpochNum), poseidonhash)
	}
	prod1 := accumulator.SetProductRecursiveFast(removeSet)
	prod2 := accumulator.SetProductRecursiveFast(insertSet)

	// Randomizers are FIXED!!! for test purpose
	ret.Randomizer1 = *big.NewInt(200)
	ret.Randomizer2 = *big.NewInt(300)
	var removedRanProd, insertedRanProd big.Int
	removedRanProd.SetInt64(1)
	insertedRanProd.SetInt64(1)
	// because gnark cannot support 2048-bits large integers, we are using the product of 8 255-bits random numbers to replace one large RSA-domain randomizer.
	for i := 0; i < 8; i++ {
		tempHash := poseidon.Poseidon(accumulator.ElementFromBigInt(&ret.Randomizer1), accumulator.ElementFromUint32(uint32(i)))
		var tempInt big.Int
		tempHash.ToBigIntRegular(&tempInt)
		removedRanProd.Mul(&removedRanProd, &tempInt)
		prod1.Mul(prod1, &tempInt)

		tempHash = poseidon.Poseidon(accumulator.ElementFromBigInt(&ret.Randomizer2), accumulator.ElementFromUint32(uint32(i)))
		tempHash.ToBigIntRegular(&tempInt)
		insertedRanProd.Mul(&insertedRanProd, &tempInt)
		prod2.Mul(prod2, &tempInt)
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generate DI representatives Takes [%.3f] Seconds \n", duration.Seconds())

	// get accumulators
	setup := *accumulator.TrustedSetup()
	maxLen := setsize * 2048 / bits.UintSize
	table := multiexp.NewPrecomputeTable(setup.G, setup.N, int(maxLen))

	unchangedSet := accumulator.GenBenchSet(int(setsize - updatedSetSize))
	unchanged := accumulator.GenRepresentatives(unchangedSet, accumulator.DIHashFromPoseidon)
	startingTime = time.Now().UTC()
	newSet1 := append(unchanged[:], insertSet...)
	// limit = 0 indicates the ProveMembershipParallelWithTableWithRandomizer is running with single thread
	_ = accumulator.ProveMembershipParallelWithTableWithRandomizer(setup.G, &insertedRanProd, setup.N, newSet1[:], 0, table)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running Generate membership proofs Takes [%.3f] Seconds \n", duration.Seconds())

	original := append(unchanged, removeSet...)
	originalProd := accumulator.SetProductRecursiveFast(original)
	originalProd = bigfft.Mul(originalProd, &removedRanProd)
	accOri := multiexp.ExpParallel(setup.G, originalProd, setup.N, table, 1, 0)
	accMid := multiexp.ExpParallel(setup.G, originalProd, setup.N, table, 1, 0)
	startingTime = time.Now().UTC()
	fmt.Println("Generate zkPoKE")
	PoKE(accMid, &removedRanProd, accOri, setup.N)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generate zkPoKE Takes [%.3f] Seconds \n", duration.Seconds())

	var accOld, accNew big.Int
	accOld.Exp(accMid, prod1, setup.N) //the accOld should already exist before the update, therefore not counted
	fmt.Println("Generate zkPoKE")
	startingTime = time.Now().UTC()
	accNew.Exp(accMid, prod2, setup.N)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generate new accumulator Takes [%.3f] Seconds \n", duration.Seconds())

	// get challenge
	transcript := zkmultiswap.SetupTranscript(&setup, &accOld, accMid, &accNew, ret.CurrentEpochNum)
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
	var deltaModL1, deltaModL2 big.Int
	deltaModL1.Mod(accumulator.Min1024, challengeL1)
	deltaModL2.Mod(accumulator.Min1024, challengeL2)
	ret.DeltaModL1 = deltaModL1
	ret.DeltaModL2 = deltaModL2

	if !ret.IsValid() {
		panic("error in TestMultiSwap, the generated test set is invalid")
	}
	//--------------------------------------------finish generating accumulator--------------------------------
	testSet := zkmultiswap.GenTestSet(updatedSetSize, accumulator.TrustedSetup())
	publicInfo := testSet.PublicPart()
	proof, err := zkmultiswap.Prove(testSet)
	if err != nil {
		fmt.Println("Error during Prove")
		panic(err)
	}
	runtime.GC()

	flag := zkmultiswap.Verify(proof, updatedSetSize, publicInfo)
	if flag {
		fmt.Println("Verification passed")
		return
	}
	fmt.Println("Verification failed")
}

// TestNotusParallel test Notus with at most 32 cores
func TestNotusParallel(setsize, updatedSetSize uint32) {
	if !isCircuitExist(updatedSetSize) {
		fmt.Println("Circuit haven't been compiled for testSetSize = ", updatedSetSize, ". Start compiling.")
		startingTime := time.Now().UTC()
		zkmultiswap.SetupZkMultiswap(updatedSetSize)
		duration := time.Now().UTC().Sub(startingTime)
		fmt.Printf("Generating a SNARK circuit for set size = %d, takes [%.3f] Seconds \n", updatedSetSize, duration.Seconds())
		runtime.GC()
	} else {
		fmt.Println("Circuit have already been compiled for test purpose.")
	}
	//--------------------------------------------generating accumulator--------------------------------
	var ret zkmultiswap.UpdateSet32
	ret.UserID = make([]uint32, updatedSetSize)
	ret.OriginalBalances = make([]uint32, updatedSetSize)
	ret.OriginalUpdEpoch = make([]uint32, updatedSetSize)
	ret.OriginalHashes = make([]big.Int, updatedSetSize)
	ret.UpdatedBalances = make([]uint32, updatedSetSize)

	ret.CurrentEpochNum = zkmultiswap.CurrentEpochNum
	for i := uint32(0); i < updatedSetSize; i++ {
		j := i*2 + 1      // no special meaning for j, just need some non-repeating positive integers
		ret.UserID[i] = j // we need to arrange user IDs in accending order for checking them efficiently
		ret.OriginalBalances[i] = j
		ret.OriginalUpdEpoch[i] = 10
		ret.OriginalHashes[i].SetInt64(int64(j))
		ret.UpdatedBalances[i] = j
	}
	ret.OriginalSum = zkmultiswap.OriginalSum
	ret.UpdatedSum = zkmultiswap.OriginalSum // UpdatedSum can be any valid positive numbers, but we are testing the case UpdatedSum = OriginalSum for simplicity

	// get slice of elements removed and inserted
	removeSet := make([]*big.Int, updatedSetSize)
	insertSet := make([]*big.Int, updatedSetSize)
	startingTime := time.Now().UTC()
	for i := uint32(0); i < updatedSetSize; i++ {
		var poseidonhash *fr.Element // this is the Poseidon part of the DI hash. We use this to build the hash chain. The original DI hash is to long to directly input into Poseidon hash
		poseidonhash, removeSet[i] = accumulator.PoseidonAndDIHash(accumulator.ElementFromUint32(ret.UserID[i]), accumulator.ElementFromUint32(ret.OriginalBalances[i]),
			accumulator.ElementFromUint32(ret.OriginalUpdEpoch[i]), accumulator.ElementFromString(ret.OriginalHashes[i].String()))
		//fmt.Println("poseidonhash i = ", poseidonhash.String())

		insertSet[i] = accumulator.DIHashPoseidon(accumulator.ElementFromUint32(ret.UserID[i]), accumulator.ElementFromUint32(ret.UpdatedBalances[i]),
			accumulator.ElementFromUint32(ret.CurrentEpochNum), poseidonhash)
	}
	prod1 := accumulator.SetProductParallel(removeSet, 4)
	prod2 := accumulator.SetProductParallel(removeSet, 4)

	// Randomizers are FIXED!!! for test purpose
	ret.Randomizer1 = *big.NewInt(200)
	ret.Randomizer2 = *big.NewInt(300)
	var removedRanProd, insertedRanProd big.Int
	removedRanProd.SetInt64(1)
	insertedRanProd.SetInt64(1)
	// because gnark cannot support 2048-bits large integers, we are using the product of 8 255-bits random numbers to replace one large RSA-domain randomizer.
	for i := 0; i < 8; i++ {
		tempHash := poseidon.Poseidon(accumulator.ElementFromBigInt(&ret.Randomizer1), accumulator.ElementFromUint32(uint32(i)))
		var tempInt big.Int
		tempHash.ToBigIntRegular(&tempInt)
		removedRanProd.Mul(&removedRanProd, &tempInt)
		prod1.Mul(prod1, &tempInt)

		tempHash = poseidon.Poseidon(accumulator.ElementFromBigInt(&ret.Randomizer2), accumulator.ElementFromUint32(uint32(i)))
		tempHash.ToBigIntRegular(&tempInt)
		insertedRanProd.Mul(&insertedRanProd, &tempInt)
		prod2.Mul(prod2, &tempInt)
	}
	duration := time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generate DI representatives Takes [%.3f] Seconds \n", duration.Seconds())

	// get accumulators
	setup := *accumulator.TrustedSetup()
	maxLen := setsize * 2048 / bits.UintSize
	table := multiexp.NewPrecomputeTable(setup.G, setup.N, int(maxLen))

	unchangedSet := accumulator.GenBenchSet(int(setsize - updatedSetSize))
	unchanged := accumulator.GenRepresentatives(unchangedSet, accumulator.DIHashFromPoseidon)
	startingTime = time.Now().UTC()
	newSet1 := append(unchanged[:], insertSet...)
	// limit = 0 indicates the ProveMembershipParallelWithTableWithRandomizer is running with single thread
	_ = accumulator.ProveMembershipParallelWithTableWithRandomizer(setup.G, &insertedRanProd, setup.N, newSet1[:], 5, table)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Running Generate membership proofs Takes [%.3f] Seconds \n", duration.Seconds())

	original := append(unchanged, removeSet...)
	originalProd := accumulator.SetProductRecursiveFast(original)
	originalProd = bigfft.Mul(originalProd, &removedRanProd)
	accOri := multiexp.ExpParallel(setup.G, originalProd, setup.N, table, 5, 0)
	accMid := multiexp.ExpParallel(setup.G, originalProd, setup.N, table, 5, 0)
	startingTime = time.Now().UTC()
	fmt.Println("Generate zkPoKE")
	PoKE(accMid, &removedRanProd, accOri, setup.N)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generate zkPoKE Takes [%.3f] Seconds \n", duration.Seconds())

	var accOld, accNew big.Int
	accOld.Exp(accMid, prod1, setup.N) //the accOld should already exist before the update, therefore not counted
	fmt.Println("Generate zkPoKE")
	startingTime = time.Now().UTC()
	accNew.Exp(accMid, prod2, setup.N)
	duration = time.Now().UTC().Sub(startingTime)
	fmt.Printf("Generate new accumulator Takes [%.3f] Seconds \n", duration.Seconds())

	// get challenge
	transcript := zkmultiswap.SetupTranscript(&setup, &accOld, accMid, &accNew, ret.CurrentEpochNum)
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
	var deltaModL1, deltaModL2 big.Int
	deltaModL1.Mod(accumulator.Min1024, challengeL1)
	deltaModL2.Mod(accumulator.Min1024, challengeL2)
	ret.DeltaModL1 = deltaModL1
	ret.DeltaModL2 = deltaModL2

	if !ret.IsValid() {
		panic("error in TestMultiSwap, the generated test set is invalid")
	}
	//--------------------------------------------finish generating accumulator--------------------------------
	table = nil
	runtime.GC()
	testSet := zkmultiswap.GenTestSet(updatedSetSize, accumulator.TrustedSetup())
	publicInfo := testSet.PublicPart()
	proof, err := zkmultiswap.Prove(testSet)
	if err != nil {
		fmt.Println("Error during Prove")
		panic(err)
	}
	runtime.GC()

	flag := zkmultiswap.Verify(proof, updatedSetSize, publicInfo)
	if flag {
		fmt.Println("Verification passed")
		return
	}
	fmt.Println("Verification failed")
}

// TestMultiSwapWithDifferentSize tests the ZK-MultiSwap under different swap size. This tests requires large memory!
func TestMultiSwapWithDifferentSize() {
	zkmultiswap.TestMultiSwap(256)  //2^8
	zkmultiswap.TestMultiSwap(512)  //2^9
	zkmultiswap.TestMultiSwap(1024) //2^10
	zkmultiswap.TestMultiSwap(2048) //2^11
	zkmultiswap.TestMultiSwap(4096) //2^12
	zkmultiswap.TestMultiSwap(8192) //2^13
}
