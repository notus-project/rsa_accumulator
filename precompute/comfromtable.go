package precompute

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/jiajunxin/rsa_accumulator/accumulator"
)

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
)

// PreTable only allows to pre-compute a power of 2 for the base g.
// base[0] should be g and n[0] is 0.
// base[i] = g^{2^{n[i]}} mod N
type PreTable struct {
	base []*big.Int
	n    []int
}

// PrintTable prints out the table for storage
func PrintTable(p *PreTable) {
	for i := 0; i < len(p.base); i++ {
		fmt.Println("BaseString", i, " = \"", p.base[i].String(), "\"")
		fmt.Println("n", i, " = ", p.n[i])
	}
}

// GenPreTable generates a precomputation table for RSA accumulators
func GenPreTable(base, N *big.Int, bitLen, tableSize int) *PreTable {
	if bitLen <= tableSize {
		panic("invalid table size, larger than intput bitLen")
	}
	var table PreTable
	table.base = make([]*big.Int, tableSize)
	table.n = make([]int, tableSize)

	stepSize := bitLen / tableSize

	table.base[0] = new(big.Int)
	table.base[0].Set(base)
	table.n[0] = 0

	var step big.Int
	step.Exp(big2, big.NewInt(int64(stepSize)), nil)
	for i := 1; i < tableSize; i++ {
		table.n[i] = table.n[i-1] + stepSize
		table.base[i] = accumulator.AccumulateNew(table.base[i-1],
			&step, N)
	}

	return &table
}

// ComputeFromTable computes g^x mod N with the pre-computation table.
func ComputeFromTable(table *PreTable, x, N *big.Int) *big.Int {
	// Todo: more checks for the validity of the table
	if len(table.base) != len(table.n) {
		panic("invalid pre-compute table, unbalanced")
	}
	if len(table.base) < 1 {
		panic("invalid pre-compute table, too small")
	}
	if x.Cmp(big0) < 1 {
		panic("invalid x, negative")
	}

	// Now, we divide x according to the n
	// We first find out how many sub part can we separate x according to the table
	length := x.BitLen()
	var iCounter int
	var xCopy big.Int
	xCopy.Set(x)
	// fmt.Println("len(table.n) = ", len(table.n))
	// fmt.Println("len(x) = ", length)
	for iCounter = 0; iCounter < len(table.n); iCounter++ {
		if table.n[iCounter] >= length {
			break
		}
	}
	if iCounter == len(table.n) {
		iCounter--
	}

	// fmt.Println("iCounter = ", iCounter)
	subX := make([]big.Int, iCounter+2)

	for i := 1; i < iCounter+1; i++ {
		var modulo big.Int
		modulo.Exp(big2, big.NewInt(int64(table.n[i]-table.n[i-1])), nil)
		subX[i-1].Mod(&xCopy, &modulo)
		//fmt.Println("subX[i-1] = ", subX[i-1].String())
		xCopy.Rsh(&xCopy, uint(table.n[i]-table.n[i-1]))
	}
	subX[iCounter].Set(&xCopy)
	//fmt.Println("subX[iCounter+1] = ", subX[iCounter+1].String())

	// --------------start of test code------------------------------
	//the following code tests the if the separation for x is correct or not
	// var prod, temp big.Int
	// for i := 0; i < iCounter+1; i++ {
	// 	if i == 0 {
	// 		prod.Add(&prod, &subX[i])
	// 		continue
	// 	}
	// 	temp.Exp(big2, big.NewInt(int64(table.n[i])), nil)
	// 	temp.Mul(&temp, &subX[i])
	// 	prod.Add(&prod, &temp)
	// }
	// fmt.Println("prod = ", prod.String())
	// fmt.Println("x = ", x.String())
	// --------------end of test code------------------------------

	// The next part can be paralleled
	var prod big.Int
	prod.SetInt64(1)
	for i := 0; i < iCounter+1; i++ {
		if i == 0 {
			temp := accumulator.AccumulateNew(table.base[0], &subX[0], N)
			prod.Mul(&prod, temp)
			continue
		}
		temp := accumulator.AccumulateNew(table.base[i], &subX[i], N)
		prod.Mul(&prod, temp)
		prod.Mod(&prod, N)
	}
	return &prod
}

// ComputeFromTableParallel computes g^x mod N with the pre-computation table in parallel.
func ComputeFromTableParallel(table *PreTable, x, N *big.Int) *big.Int {
	// Todo: more checks for the validity of the table
	if len(table.base) != len(table.n) {
		panic("invalid pre-compute table, unbalanced")
	}
	if len(table.base) < 1 {
		panic("invalid pre-compute table, too small")
	}
	if x.Cmp(big0) < 1 {
		panic("invalid x, negative")
	}

	// Now, we divide x according to the n
	// We first find out how many sub part can we separate x according to the table
	length := x.BitLen()
	var iCounter int
	var xCopy big.Int
	xCopy.Set(x)
	for iCounter = 0; iCounter < len(table.n); iCounter++ {
		if table.n[iCounter] >= length {
			break
		}
	}
	if iCounter == len(table.n) {
		iCounter--
	}

	subX := make([]big.Int, iCounter+2)
	for i := 1; i < iCounter+1; i++ {
		var modulo big.Int
		modulo.Exp(big2, big.NewInt(int64(table.n[i]-table.n[i-1])), nil)
		subX[i-1].Mod(&xCopy, &modulo)
		xCopy.Rsh(&xCopy, uint(table.n[i]-table.n[i-1]))
	}
	subX[iCounter].Set(&xCopy)

	// The next part can be paralleled
	var prod big.Int
	prod.SetInt64(1)
	c := make(chan *big.Int, iCounter)
	for i := 0; i < iCounter+1; i++ {
		if i == 0 {
			go getAccumulate(table.base[0], &subX[0], N, c)
			// temp := accumulator.AccumulateNew(table.base[0], &subX[0], N)
			// prod.Mul(&prod, temp)
			continue
		}
		go getAccumulate(table.base[i], &subX[i], N, c)
		//temp := accumulator.AccumulateNew(table.base[i], &subX[i], N)
	}

	var mutex sync.Mutex
	i := 0
	for v := range c {
		mutex.Lock()
		prod.Mul(&prod, v)
		prod.Mod(&prod, N)
		i++
		mutex.Unlock()
		if i == iCounter+1 {
			close(c)
			break
		}
	}

	return &prod
}

func getAccumulate(base, exp, N *big.Int, c chan *big.Int) {
	var ret big.Int
	ret.Exp(base, exp, N)
	c <- &ret
}
