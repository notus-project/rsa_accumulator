package proof

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"runtime"

	comp "github.com/rsa_accumulator/complex"
)

const (
	squareNum = 4
)

var (
	// 0's precomputed Hurwitz GCRD: 0, 0, 0, 0
	hGCRD0 = comp.NewHurwitzInt(big0, big0, big0, big0, false)
	// 1's precomputed Hurwitz GCRD: 1, 0, 0, 0
	hGCRD1 = comp.NewHurwitzInt(big1, big0, big0, big0, false)
	// 2's precomputed Hurwitz GCRD: 1, 1, 0, 0
	hGCRD2 = comp.NewHurwitzInt(big1, big1, big0, big0, false)
	// 3's precomputed Hurwitz GCRD: 1, 1, 1, 0
	hGCRD3 = comp.NewHurwitzInt(big1, big1, big1, big0, false)
	// 4's precomputed Hurwitz GCRD: 2, 0, 0, 0
	hGCRD4 = comp.NewHurwitzInt(big2, big0, big0, big0, false)
	// 5's precomputed Hurwitz GCRD: 2, 1, 0, 0
	hGCRD5 = comp.NewHurwitzInt(big2, big1, big0, big0, false)
	// 6's precomputed Hurwitz GCRD: 2, 1, 1, 0
	hGCRD6 = comp.NewHurwitzInt(big2, big1, big1, big0, false)
	// 7's precomputed Hurwitz GCRD: 2, 1, 1, 1
	hGCRD7 = comp.NewHurwitzInt(big2, big1, big1, big1, false)
	// 8's precomputed Hurwitz GCRD: 2, 2, 0, 0
	hGCRD8 = comp.NewHurwitzInt(big2, big2, big0, big0, false)
	// precomputed Hurwitz GCRDs for small integers
	precomputedHurwitzGCRDs = [9]*comp.HurwitzInt{
		hGCRD0, hGCRD1, hGCRD2, hGCRD3, hGCRD4, hGCRD5, hGCRD6, hGCRD7, hGCRD8,
	}
	numCPU = runtime.NumCPU()
)

// FourSquare is the LagrangeFourSquareLipmaa representation of a positive integer
// w <- LagrangeFourSquareLipmaa(mu), mu = w = W1^2 + W2^2 + W3^2 + W4^2
type FourSquare [squareNum]*big.Int

// NewFourSquare creates a new FourSquare
func NewFourSquare(w1 *big.Int, w2 *big.Int, w3 *big.Int, w4 *big.Int) FourSquare {
	w1.Abs(w1)
	w2.Abs(w2)
	w3.Abs(w3)
	w4.Abs(w4)
	// sort the four big integers in descending order
	if w1.Cmp(w2) == -1 {
		w1, w2 = w2, w1
	}
	if w1.Cmp(w3) == -1 {
		w1, w3 = w3, w1
	}
	if w1.Cmp(w4) == -1 {
		w1, w4 = w4, w1
	}
	if w2.Cmp(w3) == -1 {
		w2, w3 = w3, w2
	}
	if w2.Cmp(w4) == -1 {
		w2, w4 = w4, w2
	}
	if w3.Cmp(w4) == -1 {
		w3, w4 = w4, w3
	}
	return FourSquare{w1, w2, w3, w4}
}

// Mul multiplies all the square numbers by n
func (f *FourSquare) Mul(n *big.Int) {
	for i := 0; i < squareNum; i++ {
		f[i].Mul(f[i], n)
	}
}

// Div divides all the square numbers by n
func (f *FourSquare) Div(n *big.Int) {
	for i := 0; i < squareNum; i++ {
		f[i].Div(f[i], n)
	}
}

// String stringnifies the FourSquare object
func (f *FourSquare) String() string {
	res := "{"
	for i := 0; i < squareNum-1; i++ {
		res += f[i].String()
		res += ", "
	}
	res += f[squareNum-1].String()
	res += "}"
	return res
}

// RangeProofCommit generates a range proof commitment for a given integer
func (f *FourSquare) RangeProofCommit(pp *PublicParameters, coins rpRandCoins) (cList [squareNum]*big.Int) {
	for i := 0; i < squareNum; i++ {
		cList[i] = new(big.Int).Exp(pp.G, f[i], pp.N)
		cList[i].Mul(cList[i], new(big.Int).Exp(pp.H, coins[i], pp.N))
	}
	return
}

// LagrangeFourSquares calculates the Lagrange four squares representation of a positive integer
// Paper: Finding the Four Squares in Lagrange’s Theorem
// Link: http://pollack.uga.edu/finding4squares.pdf (page 6)
// The input should be an odd positive integer no less than 9
func LagrangeFourSquares(n *big.Int) (FourSquare, error) {
	if n.Sign() == 0 {
		res := NewFourSquare(hGCRD0.ValInt())
		return res, nil
	}
	n = new(big.Int).Set(n)
	// n = 2^e * n', n' is odd
	e := big.NewInt(0)
	for n.Bit(0) == 0 {
		n.Rsh(n, 1)
		e.Add(e, big1)
	}
	var hurwitzGCRD *comp.HurwitzInt

	if n.Cmp(big8) <= 0 {
		hurwitzGCRD = precomputedHurwitzGCRDs[n.Int64()]
	} else {
		primeProd, err := preCompute(n)
		if err != nil {
			return FourSquare{}, err
		}
		for {
			s, p, err := randomTrails(n, primeProd)
			if err != nil {
				return FourSquare{}, err
			}
			hurwitzGCRD, err = denouement(n, s, p)
			if err != nil {
				return FourSquare{}, err
			}
			w1, w2, w3, w4 := hurwitzGCRD.ValInt()
			if Verify(n, [squareNum]*big.Int{w1, w2, w3, w4}) {
				break
			}
		}
	}

	// if x'^2 + Y'^2 + Z'^2 + W'^2 = n'
	// then x^2 + Y^2 + Z^2 + W^2 = n for x, Y, Z, W defined by
	// (1 + i)^e * (x' + Y'i + Z'j + W'k) = (x + Yi + Zj + Wk)
	// Hurwitz integer: 1 + i
	//hurwitz1PlusI := clx.NewHurwitzInt(big1, big1, big0, big0, false)
	//hurwitzProd := clx.NewHurwitzInt(big1, big0, big0, big0, false)
	//for e.Sign() > 0 {
	//	hurwitzProd.Prod(hurwitzProd, hurwitz1PlusI)
	//	e.Sub(e, big1)
	//}
	// Gaussian integer: 1 + i
	gaussian1PlusI := comp.NewGaussianInt(big1, big1)
	gaussianProd := comp.NewGaussianInt(big1, big0)
	for e.Sign() > 0 {
		gaussianProd.Prod(gaussianProd, gaussian1PlusI)
		e.Sub(e, big1)
	}
	hurwitzProd := comp.NewHurwitzInt(gaussianProd.R, gaussianProd.I, big0, big0, false)
	hurwitzProd.Prod(hurwitzProd, hurwitzGCRD)
	w1, w2, w3, w4 := hurwitzProd.ValInt()
	fs := NewFourSquare(w1, w2, w3, w4)
	return fs, nil
}

// preCompute determine the primes not exceeding log n and compute their product
// the function only handles positive integers larger than 8
func preCompute(n *big.Int) (*big.Int, error) {
	if n.Cmp(big8) <= 0 {
		return nil, errors.New("n should be larger than 8")
	}
	logN := log2(n)
	var (
		// primes in [2, 8]
		primes = []*big.Int{big2, big3, big5, big7}
		// product of primes, 2 * 3 * 5 * 7 = 210
		primeProd = big.NewInt(210)
		// starting from 9
		idx = big.NewInt(9)
	)
	for idx.Cmp(logN) < 1 {
		isPrime := true
		for _, prime := range primes {
			mod := new(big.Int).Mod(idx, prime)
			if mod.Sign() == 0 {
				isPrime = false
				break
			}
		}
		if isPrime {
			newPrime := new(big.Int).Set(idx)
			primes = append(primes, newPrime)
			primeProd.Mul(primeProd, newPrime)
		}
		// increase index by 2, skip even numbers
		idx.Add(idx, big2)
	}
	return primeProd, nil
}

func randomTrails(n, primeProd *big.Int) (*big.Int, *big.Int, error) {
	nPow5Div2 := new(big.Int).Exp(n, big5, nil)
	nPow5Div2.Rsh(nPow5Div2, 1)
	preP := new(big.Int).Set(primeProd)
	preP.Mul(preP, n)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batches := rangeDiv(nPow5Div2, numCPU)
	resChan := make(chan findSResult)
	for _, batch := range batches {
		go findSRoutine(ctx, batch[0], batch[1], preP, resChan)
	}
	res := <-resChan
	return res.s, res.p, res.err
}

func findSRoutine(ctx context.Context, start, end, preP *big.Int, resChan chan<- findSResult) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			s, p, err := pickS(start, end, preP)
			if err != nil {
				select {
				case resChan <- findSResult{err: err}:
					return
				default:
					return
				}
			}
			targetMod := new(big.Int).Mod(bigNeg1, p)
			// test if s^2 = -1 (mod p)
			// if so, continue to the next step, otherwise, repeat this step
			if new(big.Int).Exp(s, big2, p).Cmp(targetMod) == 0 {
				ctx.Done()
				select {
				case resChan <- findSResult{s: s, p: p}:
					return
				default:
					return
				}
			}
		}
	}
}

type findSResult struct {
	s, p *big.Int
	err  error
}

func pickS(start, end, preP *big.Int) (*big.Int, *big.Int, error) {
	var (
		k, u *big.Int
		err  error
	)
	// choose k' in [start, end)
	gap := new(big.Int).Sub(end, start)
	if k, err = rand.Int(rand.Reader, gap); err != nil {
		return nil, nil, err
	}
	k.Add(k, start)
	// construct k, k = 2k' + 1
	k.Lsh(k, 1)
	k.Add(k, big1)
	// p = {Product of primes} * n * k - 1 = preP * k - 1
	p := new(big.Int).Set(preP)
	p.Mul(p, k)
	p.Sub(p, big1)
	pMinus1 := new(big.Int).Set(p)
	pMinus1.Sub(pMinus1, big1)
	// choose u from [1, p - 1]
	if u, err = rand.Int(rand.Reader, pMinus1); err != nil {
		return nil, nil, err
	}
	u.Add(u, big1)
	// compute s = u^((p - 1) / 4) mod p
	powU := new(big.Int).Set(pMinus1)
	powU.Div(powU, big4)
	s := new(big.Int).Exp(u, powU, p)
	return s, p, nil
}

func denouement(n, s, p *big.Int) (*comp.HurwitzInt, error) {
	// compute A + Bi := gcd(s + i, p)
	// Gaussian integer: s + i
	gaussianInt := comp.NewGaussianInt(s, big1)
	// Gaussian integer: p
	gaussianP := comp.NewGaussianInt(p, big0)
	gcd := new(comp.GaussianInt)
	gcd.GCD(gaussianInt, gaussianP)
	// compute gcrd(A + Bi + j, n), normalized to have integer component
	// Hurwitz integer: A + Bi + j
	hurwitzInt := comp.NewHurwitzInt(gcd.R, gcd.I, big1, big0, false)
	// Hurwitz integer: n
	hurwitzN := comp.NewHurwitzInt(n, big0, big0, big0, false)
	gcrd := new(comp.HurwitzInt)
	gcrd.GCRD(hurwitzInt, hurwitzN)

	return gcrd, nil
}

// Verify checks if the four-square sum is equal to the original integer
// i.e. target = w1^2 + w2^2 + w3^2 + w4^2
func Verify(target *big.Int, fs [squareNum]*big.Int) bool {
	sum := new(big.Int).Mul(fs[0], fs[0])
	for i := 1; i < squareNum; i++ {
		sum.Add(sum, new(big.Int).Mul(fs[i], fs[i]))
	}
	return sum.Cmp(target) == 0
}