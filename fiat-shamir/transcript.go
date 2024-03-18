package fiatshamir

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

var min253 big.Int

func init() {
	min253.SetInt64(1)
	_ = min253.Lsh(&min253, bitLimit-1)
}

// ChallengeLength denotes the maximum length of challenge
type ChallengeLength uint32

const (
	// bit limit, used because of limit in gnark
	bitLimit = 240
	// Based on the Miller-Robin test, the probability to have a non-prime probability is less than 1/(securityParaHash*4)
	securityParameter = 30
	// Default lenght is 256-bit
	Default ChallengeLength = iota
	// Max252 lenght is 252-bit
	Max252
)

// Transcript strores the statement to generate challenge in the info as a slice of strings
type Transcript struct {
	info      []string
	maxlength ChallengeLength
}

// Print outputs the info in the transcript
func (transcript *Transcript) Print() {
	fmt.Println("The transcript has ", len(transcript.info), "strings as info.")
	for i := range transcript.info {
		fmt.Println("Info[", i, "] = ", transcript.info[i])
	}
}

// InitTranscript inits a transcript with the input strings
func InitTranscript(input []string, length ChallengeLength) *Transcript {
	var ret Transcript
	ret.maxlength = length
	// we need a deep copy to make sure the transcript will not be changed
	ret.info = append(ret.info, input...)
	return &ret
}

// Append add new info into the transcript
func (transcript *Transcript) Append(newInfo string) {
	transcript.info = append(transcript.info, newInfo)
}

// AppendSlice add new slice info into the transcript
func (transcript *Transcript) AppendSlice(newInfo []string) {
	transcript.info = append(transcript.info, newInfo...)
}

// GetChallengeAndAppendTranscript returns a challenge and appends the challenge as part of the transcript
func (transcript *Transcript) GetChallengeAndAppendTranscript() *big.Int {
	var ret big.Int
	ret.Set(HashToPrime(transcript.info, transcript.maxlength))
	transcript.Append(ret.String())
	return &ret
}

// GetPrimeChallengeUsingTranscript returns a challenge and appends the challenge as part of the transcript
func (transcript *Transcript) GetPrimeChallengeUsingTranscript() *big.Int {
	var ret big.Int
	ret.Set(HashToPrime(transcript.info, transcript.maxlength))
	transcript.Append(ret.String())
	return &ret
}

// GetIntChallengeUsingTranscript returns a challenge and appends the challenge as part of the transcript
func (transcript *Transcript) GetIntChallengeUsingTranscript() *big.Int {
	var ret big.Int
	ret.Set(HashToInt(transcript.info, transcript.maxlength))
	transcript.Append(ret.String())
	return &ret
}

func wrapNumber(input []byte, length ChallengeLength) *big.Int {
	var ret big.Int
	ret.SetBytes(input)
	switch length {
	case Default:
		return &ret
	case Max252:
		if ret.Cmp(&min253) != 0 {
			ret.Mod(&ret, &min253)
		}
		return &ret
	default:
		return &ret
	}
}

// HashToPrime takes the input into Poseidon and take the hash output to input repeatedly until we hit a prime number
// length of challenge is based on the input length. Default is 256-bit.
func HashToPrime(input []string, length ChallengeLength) *big.Int {
	h := sha256.New()
	for i := 0; i < len(input); i++ {
		_, err := h.Write([]byte(input[i]))
		if err != nil {
			panic(err)
		}
	}
	hashTemp := h.Sum(nil)
	ret := wrapNumber(hashTemp, length)
	flag := false
	for !flag {
		flag = ret.ProbablyPrime(securityParameter)
		if !flag {
			h.Reset()
			_, err := h.Write(ret.Bytes())
			if err != nil {
				panic(err)
			}
			hashTemp = h.Sum(nil)
			ret = wrapNumber(hashTemp, length)
		}
	}
	return ret
}

// HashToInt takes the input into Sha256 and take the hash output as an integer
// length of challenge is based on the input length. Default is 256-bit.
func HashToInt(input []string, length ChallengeLength) *big.Int {
	h := sha256.New()
	for i := 0; i < len(input); i++ {
		_, err := h.Write([]byte(input[i]))
		if err != nil {
			panic(err)
		}
	}
	hashTemp := h.Sum(nil)
	ret := wrapNumber(hashTemp, length)
	return ret
}
