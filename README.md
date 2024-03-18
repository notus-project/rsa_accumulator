# Notus: Dynamic Proofs of Liabilities from Zero-knowledge RSA Accumulators

A prototype for Notus, a dynamic Proofs of Liabilities system based on zero-knowledge RSA accumulators and SNARKs. 

DO NOT use in the production environment.

Require Golang 1.19 or above.

To run the experiment, simply run
```bash
go build
./rsa_accumulator
```

## Test the Solidity Smart contract

The solidity smart contract for verifying the SNARK circuit has already been generated as 
```bash
Notuscontract_g16.sol
```

If you wish to generate from scratch by yourself, you can use the following code:
```bash
cd zkmultiswap/gnark-tests/solidity
go generate
go test
```

It needs `solc` and `abigen` (1.10.17-stable).