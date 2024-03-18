// Package proof zkPoKE
// Protocol PoKE for R_{PoKE}
// Paper: Batching Techniques for Accumulators with Applications to IOPs and Stateless Blockchains
// Link: https://eprint.iacr.org/2018/1188.pdf
package proof

import (
	"crypto/rand"
	"errors"
	"math/big"

	fiatshamir "github.com/jiajunxin/rsa_accumulator/fiat-shamir"
)

// MultiExp computes g^x * h^r mod n
func MultiExp(g, x, h, r, n *big.Int) *big.Int {
	var temp1, temp2 big.Int
	temp1.Exp(g, x, n)
	temp2.Exp(h, r, n)
	temp1.Mul(&temp1, &temp2)
	temp1.Mod(&temp1, n)
	return &temp1
}

// PoKEStarProof contains the proofs for PoKE
type PoKEStarProof struct {
	Q *big.Int
	R *big.Int
}

// PoKEStarProve proves knowledge of x s.t.  g^x = C
func PoKEStarProve(pp *PublicParameters, C, x *big.Int) (*PoKEStarProof, error) {
	var ret PoKEStarProof
	ret.Q = new(big.Int)
	ret.R = new(big.Int)
	var temp, q, l big.Int
	temp.Exp(pp.G, x, pp.N)
	if temp.Cmp(C) != 0 {
		return nil, errors.New("PoKEStar inputs a invalid statement")
	}

	transcript := fiatshamir.InitTranscript([]string{"PoKEStar", pp.G.String(), pp.N.String(), C.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	q.DivMod(x, &l, ret.R)
	ret.Q.Exp(pp.G, &q, pp.N)
	return &ret, nil
}

// PoKEStarVerify checks the proof, returns true if everything is good
func PoKEStarVerify(pp *PublicParameters, C *big.Int, proof *PoKEStarProof) bool {
	if proof == nil {
		return false
	}
	var temp, l big.Int
	transcript := fiatshamir.InitTranscript([]string{"PoKEStar", pp.G.String(), pp.N.String(), C.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())

	temp.Set(MultiExp(proof.Q, &l, pp.G, proof.R, pp.N))
	return temp.Cmp(C) == 0
}

// ZKPoKEProof contains the proofs for ZKPoKE
type ZKPoKEProof struct {
	z    *big.Int
	Ag   *big.Int
	Au   *big.Int
	Qg   *big.Int
	Qu   *big.Int
	rx   *big.Int
	rrho *big.Int
}

// ZKPoKEProve proves in zero-knowledge of knowledge x s.t. u^x =w mod N
func ZKPoKEProve(pp *PublicParameters, u, x, w *big.Int) (*ZKPoKEProof, error) {
	var ret ZKPoKEProof
	var temp, c, l big.Int
	temp.Exp(u, x, pp.N)
	if temp.Cmp(w) != 0 {
		return nil, errors.New("ZKPoKEProve inputs a invalid statement")
	}

	b := new(big.Int).Set(pp.N)
	lsh := 2*securityParam - 2
	b.Lsh(b, uint(lsh))
	k, err := rand.Int(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	rhox, err := rand.Int(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	rhok, err := rand.Int(rand.Reader, b)
	if err != nil {
		return nil, err
	}

	ret.z = new(big.Int).Set(MultiExp(pp.G, x, pp.H, rhox, pp.N))
	ret.Ag = new(big.Int).Set(MultiExp(pp.G, k, pp.H, rhok, pp.N))
	ret.Au = new(big.Int).Exp(u, k, pp.N)

	transcript := fiatshamir.InitTranscript([]string{"ZKPoKE", pp.G.String(), pp.H.String(),
		pp.N.String(), u.String(), w.String(), ret.z.String(), ret.Ag.String(), ret.Au.String()}, fiatshamir.Max252)
	c.Set(transcript.GetIntChallengeUsingTranscript())
	l.Set(transcript.GetPrimeChallengeUsingTranscript())

	var sx, srho big.Int //sx = k+ cx, srho = rhok + c*rhox
	sx.Mul(&c, x)
	sx.Add(&sx, k)
	srho.Mul(&c, rhox)
	srho.Add(&srho, rhok)

	var qx, rx, qrho, rrho big.Int // qx*l + rx = sx, qrho*l + rrho = srho
	qx.DivMod(&sx, &l, &rx)
	qrho.DivMod(&srho, &l, &rrho)

	ret.Qg = new(big.Int).Set(MultiExp(pp.G, &qx, pp.H, &qrho, pp.N))
	ret.Qu = new(big.Int).Exp(u, &qx, pp.N)
	ret.rx = new(big.Int).Set(&rx)
	ret.rrho = new(big.Int).Set(&rrho)

	return &ret, nil
}

// ZKPoKEVerify checks the proof, returns true if everything is good
func ZKPoKEVerify(pp *PublicParameters, u, w *big.Int, proof *ZKPoKEProof) bool {
	if proof == nil {
		return false
	}
	var c, l big.Int
	transcript := fiatshamir.InitTranscript([]string{"ZKPoKE", pp.G.String(), pp.H.String(),
		pp.N.String(), u.String(), w.String(), proof.z.String(), proof.Ag.String(), proof.Au.String()}, fiatshamir.Max252)
	c.Set(transcript.GetIntChallengeUsingTranscript())
	l.Set(transcript.GetPrimeChallengeUsingTranscript())

	var lhs, rhs big.Int
	// checking the fist condition
	lhs.Exp(proof.Qg, &l, pp.N)
	lhs.Mul(&lhs, MultiExp(pp.G, proof.rx, pp.H, proof.rrho, pp.N))
	lhs.Mod(&lhs, pp.N)

	rhs.Exp(proof.z, &c, pp.N)
	rhs.Mul(&rhs, proof.Ag)
	rhs.Mod(&rhs, pp.N)
	if lhs.Cmp(&rhs) != 0 {
		return false
	}
	lhs.Set(MultiExp(proof.Qu, &l, u, proof.rx, pp.N))
	rhs.Exp(w, &c, pp.N)
	rhs.Mul(&rhs, proof.Au)
	rhs.Mod(&rhs, pp.N)
	return lhs.Cmp(&rhs) == 0
}

// PoEProof contains the proofs for PoE
type PoEProof struct {
	Q *big.Int
}

// PoEProve proves g^x = C
func PoEProve(base, mod, C, x *big.Int) (*PoEProof, error) {
	var ret PoEProof
	ret.Q = new(big.Int)
	var temp, q, l big.Int
	temp.Exp(base, x, mod)
	if temp.Cmp(C) != 0 {
		return nil, errors.New("PoKEStar inputs a invalid statement")
	}

	transcript := fiatshamir.InitTranscript([]string{"PoE", base.String(), mod.String(), C.String(), x.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	q.Div(x, &l)
	ret.Q.Exp(base, &q, mod)
	return &ret, nil
}

// PoEVerify checks the proof, returns true if everything is good
func PoEVerify(base, mod, C, x *big.Int, proof *PoEProof) bool {
	if proof == nil {
		return false
	}
	var temp, l, r big.Int
	transcript := fiatshamir.InitTranscript([]string{"PoE", base.String(), mod.String(), C.String(), x.String()}, fiatshamir.Max252)
	l.Set(transcript.GetPrimeChallengeUsingTranscript())
	r.Mod(x, &l)
	temp.Set(MultiExp(proof.Q, &l, base, &r, mod))
	return temp.Cmp(C) == 0
}
