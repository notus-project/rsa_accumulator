package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/rsa_accumulator/proof"
)

func main() {
	//for i := 0; i < 100; i++ {
	//	x, err := rand.Prime(rand.Reader, 40)
	//	handleError(err)
	//	fmt.Println(x)
	//}
	bitLen := flag.Int("bit", 500, "bit length of the modulus")
	tries := flag.Int("try", 500, "number of tries")
	flag.Parse()
	f, err := os.OpenFile("test_"+strconv.Itoa(*bitLen)+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	handleError(err)
	defer func(f *os.File) {
		err := f.Close()
		handleError(err)
	}(f)

	var totalTime float64
	for i := 0; i < *tries; i++ {
		_, err = f.WriteString(time.Now().String() + "\n")
		handleError(err)
		target := randOddGen(*bitLen)
		//target := randGen(*bitLen)
		handleError(err)
		_, err = f.WriteString(fmt.Sprintf("%d\n", target.BitLen()))
		handleError(err)
		_, err = f.WriteString(target.String() + "\n")
		handleError(err)
		start := time.Now()
		//fs, err := proof.UnconditionalLagrangeFourSquares(target)
		fs, err := proof.LagrangeFourSquares(target)
		handleError(err)
		currTime := time.Now()
		timeInterval := currTime.Sub(start)
		fmt.Println("No.", i, ":", timeInterval)
		totalTime += timeInterval.Seconds()
		secondsStr := fmt.Sprintf("%f", timeInterval.Seconds())
		_, err = f.WriteString(secondsStr + "\n")
		handleError(err)
		if ok := proof.Verify(target, fs); !ok {
			fmt.Println(target)
			fmt.Println(fs)
			panic("verification failed")
		}
	}
	fmt.Printf("average: %f\n", totalTime/float64(*tries))
	//u := big.NewInt(123)
	//x := big.NewInt(2)
	//w := new(big.Int).Exp(u, x, nil)
	//g := new(big.Int)
	//g.SetString(accumulator.G2048String, 10)
	//h := new(big.Int)
	//h.SetString(accumulator.H2048String, 10)
	//n := new(big.Int)
	//n.SetString(accumulator.N2048String, 10)
	//pp := proof.NewPublicParameters(n, g, h)
	//prover := proof.NewExpProver(pp)
	//verifier := proof.NewExpVerifier(pp)
	//pf, err := prover.Prove(u, w, x)
	//handleError(err)
	//ok, err := verifier.Verify(pf, u, w)
	//handleError(err)
	//fmt.Println(ok)
	//return
}

func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

func randOddGen(bitLen int) *big.Int {
	randLmt := new(big.Int).Lsh(big.NewInt(1), uint(bitLen-2))
	target, err := rand.Int(rand.Reader, randLmt)
	target.Lsh(target, 1)
	handleError(err)
	target.Add(target, big.NewInt(1))
	target.Add(target, new(big.Int).Lsh(big.NewInt(1), uint(bitLen-1)))
	return target
}

func randGen(bitLen int) *big.Int {
	randLmt := new(big.Int).Lsh(big.NewInt(1), uint(bitLen))
	randLmt.Sub(randLmt, big.NewInt(1))
	target, err := rand.Int(rand.Reader, randLmt)
	handleError(err)
	return target
}
