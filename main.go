package main

import (
	"fmt"

	"github.com/pkg/profile"

	"github.com/rsa_accumulator/accumulator"
)

func main() {
	defer profile.Start(profile.CPUProfile).Stop()
	fmt.Println("test in main")
	// accumulator.ManualBench(1000)
	// accumulator.ManualBenchIter(1000)
	accumulator.ManualBenchParallel(1000)
}
