package accumulator

import (
	"fmt"
	"math/big"
	"time"

	"github.com/jiajunxin/multiexp"
	"github.com/remyoudompheng/bigfft"
)

func init() {
	_ = Min1024.Lsh(big1, 1024-1)
	_ = Min2048.Lsh(big1, RSABitLength-1)
	P.SetString(PString, 10)
	A.SetString(AString, 10)
	B.SetString(BString, 10)
}

// TrustedSetup returns a pointer to AccumulatorSetup with 2048 bits key length
func TrustedSetup() *Setup {
	ret := &Setup{
		N: &big.Int{},
		G: &big.Int{},
		H: &big.Int{},
	}
	ret.N.SetString(N2048String, 10)
	ret.G.SetString(G2048String, 10)
	ret.H.SetString(H2048String, 10)
	return ret
}

// GenRepresentatives generates different representatives that can be inputted into RSA accumulator
func GenRepresentatives(set []string, encodeType EncodeType) []*big.Int {
	switch encodeType {
	case HashToPrimeFromSha256:
		return genRepWithHashToPrimeFromSHA256(set)
	case DIHashFromPoseidon:
		return genRepWithDIHashFromPoseidon(set)
	default:
		return genRepWithHashToPrimeFromSHA256(set)
	}
}

// AccAndProve generates the accumulator with all the memberships precomputed
func AccAndProve(set []string, encodeType EncodeType, setup *Setup) (*big.Int, []*big.Int) {
	startingTime := time.Now().UTC()
	rep := GenRepresentatives(set, encodeType)
	endingTime := time.Now().UTC()
	var duration = endingTime.Sub(startingTime)
	fmt.Printf("Running GenRepresentatives Takes [%.3f] Seconds \n",
		duration.Seconds())

	proofs := ProveMembership(setup.G, setup.N, rep)
	// we generate the accumulator by anyone of the membership proof raised to its power to save some calculation
	acc := AccumulateNew(proofs[0], rep[0], setup.N)

	return acc, proofs
}

// AccAndProveIter iteratively generates the accumulator with all the memberships precomputed
func AccAndProveIter(set []string, encodeType EncodeType, setup *Setup) (*big.Int, []*big.Int) {
	rep := GenRepresentatives(set, encodeType)

	proofs := ProveMembershipIter(*setup.G, setup.N, rep)
	// we generate the accumulator by anyone of the membership proof raised to its power to save some calculation
	acc := AccumulateNew(proofs[0], rep[0], setup.N)

	return acc, proofs
}

// ProveMembershipSingleThreadWithRandomizer uses divide-and-conquer method to pre-compute the all membership proofs in time O(nlog(n))
func ProveMembershipSingleThreadWithRandomizer(base, randomizer, N *big.Int, set []*big.Int, table *multiexp.PreTable) []*big.Int {
	// the left part of proof need to accumulate the right part of the set, vice versa.
	leftProd := SetProductRecursiveFast(set[len(set)/2:])
	rightProd := SetProductRecursiveFast(set[0 : len(set)/2])
	leftProd = bigfft.Mul(leftProd, randomizer)
	rightProd = bigfft.Mul(rightProd, randomizer)

	leftleftProd := SetProductRecursiveFast(set[len(set)/4 : len(set)/2])
	leftrightProd := SetProductRecursiveFast(set[0 : len(set)/4])
	rightleftProd := SetProductRecursiveFast(set[len(set)*3/4:])
	rightrightProd := SetProductRecursiveFast(set[len(set)/2 : len(set)*3/4])

	var inputExp [4]*big.Int
	inputExp[0] = bigfft.Mul(leftProd, leftleftProd)
	inputExp[1] = bigfft.Mul(leftProd, leftrightProd)
	inputExp[2] = bigfft.Mul(rightProd, rightleftProd)
	inputExp[3] = bigfft.Mul(rightProd, rightrightProd)
	bases := multiexp.FourfoldExpPrecomputed(base, N, inputExp, table)

	proofs := ProveMembership(bases[0], N, set[0:len(set)/4])
	proofs = append(proofs, ProveMembership(bases[1], N, set[len(set)/4:len(set)/2])...)
	proofs = append(proofs, ProveMembership(bases[2], N, set[len(set)/2:len(set)*3/4])...)
	proofs = append(proofs, ProveMembership(bases[3], N, set[len(set)*3/4:])...)
	return proofs
}

// ProveMembership uses divide-and-conquer method to pre-compute the all membership proofs in time O(nlog(n))
func ProveMembership(base, N *big.Int, set []*big.Int) []*big.Int {

	if len(set) <= 4 {
		return handleSmallSet(base, N, set)
	}

	leftProd := SetProductRecursiveFast(set[len(set)/2:])
	rightProd := SetProductRecursiveFast(set[0 : len(set)/2])
	leftleftProd := SetProductRecursiveFast(set[len(set)/4 : len(set)/2])
	leftrightProd := SetProductRecursiveFast(set[0 : len(set)/4])
	rightleftProd := SetProductRecursiveFast(set[len(set)*3/4:])
	rightrightProd := SetProductRecursiveFast(set[len(set)/2 : len(set)*3/4])

	var inputExp [4]*big.Int
	inputExp[0] = bigfft.Mul(leftProd, leftleftProd)
	inputExp[1] = bigfft.Mul(leftProd, leftrightProd)
	inputExp[2] = bigfft.Mul(rightProd, rightleftProd)
	inputExp[3] = bigfft.Mul(rightProd, rightrightProd)

	bases := multiexp.FourfoldExp(base, N, inputExp)
	proofs := ProveMembership(bases[0], N, set[0:len(set)/4])
	proofs = append(proofs, ProveMembership(bases[1], N, set[len(set)/4:len(set)/2])...)
	proofs = append(proofs, ProveMembership(bases[2], N, set[len(set)/2:len(set)*3/4])...)
	proofs = append(proofs, ProveMembership(bases[3], N, set[len(set)*3/4:])...)
	return proofs
}

// ProofNode is the linked-list node for iterating proofs
type proofNode struct {
	left  int // left index of proofs
	right int // right index of proofs
	proof *big.Int
	next  *proofNode
}

// ProveMembershipIter uses divide-and-conquer method to pre-compute the all membership proofs iteratively
func ProveMembershipIter(base big.Int, N *big.Int, set []*big.Int) []*big.Int {
	if len(set) <= 0 {
		return nil
	}
	var (
		header = &proofNode{
			right: len(set),
			proof: &base,
		}
		iter       = header
		finishFlag = true
	)

	for finishFlag {
		finishFlag = false
		iter = header
		for iter != nil {
			if iter.right-iter.left <= 1 {
				iter = iter.next
				continue
			}
			iter = insertNewProofNode(iter, N, set)
			finishFlag = true
		}
	}

	proofs := make([]*big.Int, 0, len(set))
	for iter = header; iter != nil; iter = iter.next {
		proofs = append(proofs, iter.proof)
	}
	return proofs
}

func insertNewProofNode(iter *proofNode, N *big.Int, set []*big.Int) *proofNode {
	left := iter.left
	right := iter.right
	mid := left + (right-left)/2
	newProofNode := &proofNode{
		left:  mid,
		right: right,
		proof: accumulateNew(iter.proof, N, set[left:mid]),
		next:  iter.next,
	}
	iter.left = left
	iter.right = mid
	iter.proof = accumulate(iter.proof, N, set[mid:right])
	iter.next = newProofNode
	return newProofNode.next
}

func handleSmallSet(base, N *big.Int, set []*big.Int) []*big.Int {
	if len(set) == 4 {
		// suppose the set is x0, x1, x2, x3, the membership for x0 is base^{x1x2x3}
		x0x1Prod := bigfft.Mul(set[0], set[1])
		x2x3Prod := bigfft.Mul(set[2], set[3])
		x0Prod := bigfft.Mul(x2x3Prod, set[1])
		x1Prod := bigfft.Mul(x2x3Prod, set[0])
		x2Prod := bigfft.Mul(x0x1Prod, set[3])
		x3Prod := bigfft.Mul(x0x1Prod, set[2])
		fourfold := multiexp.FourfoldExp(base, N, [4]*big.Int{x0Prod, x1Prod, x2Prod, x3Prod})
		return fourfold[:]
	}
	if len(set) == 3 {
		// suppose the set is x0, x1, x2, the membership for x0 is base^{x1x2}
		x0Prod := bigfft.Mul(set[1], set[2])
		x1Prod := bigfft.Mul(set[0], set[2])
		x2Prod := bigfft.Mul(set[0], set[1])
		doubleExp := multiexp.DoubleExp(base, [2]*big.Int{x0Prod, x1Prod}, N)
		ret := doubleExp[:]
		ret = append(ret, AccumulateNew(base, x2Prod, N))
		return ret
	}
	if len(set) == 2 {
		doubleExp := multiexp.DoubleExp(base, [2]*big.Int{set[1], set[0]}, N)
		return doubleExp[:]
	}
	if len(set) == 1 {
		ret := make([]*big.Int, 1)
		ret[0] = new(big.Int)
		ret[0].Set(base)
		return ret
	}

	// Should never reach here
	fmt.Println("Error in handleSmallSet, set size =", len(set))
	panic("Error in handleSmallSet, set size")
}

// AccumulateNew calculates g^{power} mod N
func AccumulateNew(g, power, N *big.Int) *big.Int {
	ret := new(big.Int).Set(g)
	ret.Exp(g, power, N)
	return ret
}

func accumulate(g, N *big.Int, set []*big.Int) *big.Int {
	for _, v := range set {
		g.Exp(g, v, N)
	}
	return g
}

// AccumulateParallel is a test function for Parallelly accumulating elements
// func AccumulateParallel(g, N *big.Int, set []*big.Int) *big.Int {
// 	// test function. Just parallel for 4 cores.
// 	var prod big.Int
// 	prod.SetInt64(1)
// 	for _, v := range set {
// 		prod.Mul(&prod, v)
// 	}
// 	bitLength := prod.BitLen()
// 	// find the decimal for the bit length
// 	g.Exp(g, &prod, N)
// 	return g
// }

func accumulateNew(g, N *big.Int, set []*big.Int) *big.Int {
	acc := new(big.Int).Set(g)
	return accumulate(acc, N, set)
}
