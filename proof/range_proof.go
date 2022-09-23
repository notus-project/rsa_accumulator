// Package proof range proof
// Variant of Lipmaa’s Compact Argument for Positivity proposed by Geoffroy Couteau et al. for range proof
// To prove an integer x lies in the range [a, b], we can show that x - a and b - x are positive by decomposing
// them as sum of four squares
// Paper: Removing the Strong RSA Assumption from Arguments over the Integers
// Link: https://eprint.iacr.org/2016/128
package proof

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"math/big"
)

const (
	rpChallengeStatement = "c = (g^x)(h^r), x is non-negative"
	sha256Len            = 32
	commitLen            = sha256Len * 5
)

var rpB = big.NewInt(4096) // bound B

// RangeProof is the proof for range proof
type RangeProof struct {
	// c = (g^x)(h^r)
	c *big.Int
	// commitment of x,
	// containing c1, c2, c3, c4, ci = (g^xi)(h^ri),
	// x = x1^2 + x2^2 + x3^2
	commitX Int3
	// the commitment delta
	commitment rpCommitment
	// the response to the challenge
	response *rpResponse
}

// NewRangeProof generates a new proof for range proof
func NewRangeProof(c *big.Int, commitX Int3, commitment rpCommitment, response *rpResponse) *RangeProof {
	return &RangeProof{
		c:          c,
		commitX:    commitX,
		commitment: commitment,
		response:   response,
	}
}

// rpCommitment is the range proof commitment generated by the prover
type rpCommitment [commitLen]byte

// rpChallenge is the challenge for range proof
type rpChallenge struct {
	statement string   // the statement for the challenge
	g, h, n   *big.Int // public parameters: G, H, N
	c4        Int4     // commitment of x containing c1, c2, c3, c4
}

// newRPChallenge generates a new challenge for range proof
func newRPChallenge(pp *PublicParameters, c4 Int4) *rpChallenge {
	return &rpChallenge{
		statement: rpChallengeStatement,
		g:         pp.G,
		h:         pp.H,
		n:         pp.N,
		c4:        c4,
	}
}

// Serialize generates the serialized data for range proof challenge in byte format
func (r *rpChallenge) serialize() []byte {
	var buf bytes.Buffer
	buf.WriteString(r.statement)
	buf.WriteString(r.g.String())
	buf.WriteString(r.h.String())
	buf.WriteString(r.n.String())
	for _, c := range r.c4 {
		buf.WriteString(c.String())
	}
	return buf.Bytes()
}

// sha256 generates the SHA256 hash of the range proof challenge
func (r *rpChallenge) sha256() []byte {
	hashF := crypto.SHA256.New()
	hashF.Write(r.serialize())
	hashResult := hashF.Sum(nil)
	return hashResult
}

// bigInt serializes the range proof challenge to bytes, generates the SHA256 hash of the byte data,
// and convert the hash to big integer
func (r *rpChallenge) bigInt() *big.Int {
	hashVal := r.sha256()
	return new(big.Int).SetBytes(hashVal)
}

// rpResponse is the response sent by the prover after receiving verifier's challenge
type rpResponse struct {
	Z4 Int4
	T4 Int4
	T  *big.Int
}

// newRPCommitment generates a new commitment for range proof
func newRPCommitment(d4 Int4, d *big.Int) rpCommitment {
	var dByteList [4][]byte
	for i := 0; i < 4; i++ {
		dByteList[i] = d4[i].Bytes()
	}
	dBytes := d.Bytes()
	hashF := crypto.SHA256.New()
	var sha256List [4][]byte
	for i, dByte := range dByteList {
		hashF.Write(dByte)
		sha256List[i] = hashF.Sum(nil)
		hashF.Reset()
	}
	var commitment rpCommitment
	for idx, s := range sha256List {
		copy(commitment[idx*sha256Len:(idx+1)*sha256Len], s)
	}
	hashF.Write(dBytes)
	copy(commitment[commitLen-sha256Len:], hashF.Sum(nil))
	return commitment
}

// RPProver refers to the Prover in zero-knowledge integer range proof
type RPProver struct {
	pp        *PublicParameters // public parameters
	x         *big.Int          // x, non-negative integer
	r         *big.Int          // r
	sp        *big.Int          // security parameter, kappa
	C         *big.Int          // c = (g^x)(h^r)
	a, b      *big.Int          // a, b, range [a, b]
	x0, r0    *big.Int          // x0 = (b-x), r0 = r
	squareX3  Int3              // three square sum of 4(b-x)(x-a) + 1 = x1^2 + x2^2 + x3^2
	commitFSX Int3              // commitment of four square of x: c1, c2, c3, ci = (g^xi)(h^ri)
	randM4    Int4              // random coins: m1, m2, m3, m4, mi is in [0, 2^(B + 2kappa)]
	randR3    Int3              // random coins: r1, r2, r3, ri is in [0, n]
	randS4    Int4              // random coins: s1, s2, s3, s4, si is in [0, 2^(2kappa)*n]
	sigma     *big.Int          // random selected parameter sigma in [0, 2^(B + 2kappa)*n]
}

// NewRPProver generates a new range proof prover
func NewRPProver(pp *PublicParameters, r, a, b *big.Int) *RPProver {
	prover := &RPProver{
		pp: pp,
		r:  r,
		a:  a,
		b:  b,
		sp: big.NewInt(securityParam),
	}
	prover.x = new(big.Int).Sub(b, a)
	prover.calC()
	return prover
}

// calculate parameter c, c = (g^x)(h^r)
func (r *RPProver) calC() *big.Int {
	r.C = new(big.Int).Exp(r.pp.G, r.x, r.pp.N)
	opt := iPool.Get().(*big.Int)
	defer iPool.Put(opt)
	r.C.Mul(r.C, opt.Exp(r.pp.H, r.r, r.pp.N))
	r.C.Mod(r.C, r.pp.N)
	return r.C
}

// Prove generates the proof for range proof
func (r *RPProver) Prove() (*RangeProof, error) {
	cx, err := r.commitForX()
	if err != nil {
		return nil, err
	}
	commitment, err := r.commit()
	if err != nil {
		return nil, err
	}
	response, err := r.response()
	if err != nil {
		return nil, err
	}
	return NewRangeProof(r.C, cx, commitment, response), nil
}

// commitForX generates the commitment for x
func (r *RPProver) commitForX() (Int3, error) {
	// calculate three squares that 4(b-x)(x-a) + 1 = x1^2 + x2^2 + x3^2
	target := iPool.Get().(*big.Int).Sub(r.b, r.x)
	defer iPool.Put(target)
	opt := iPool.Get().(*big.Int).Sub(r.x, r.a)
	defer iPool.Put(opt)
	target.Mul(target, opt)
	target.Lsh(target, 2)
	target.Add(target, big1)
	ts, err := ThreeSquares(target)
	if err != nil {
		return Int3{}, err
	}
	r.squareX3 = ts
	// calculate commitment for x
	var rc Int3
	if rc, err = newThreeRandCoins(r.pp.N); err != nil {
		return Int3{}, err
	}
	r.randR3 = rc
	c3 := newRPCommitFromFS(r.pp, rc, ts)
	r.commitFSX = c3
	return c3, nil
}

// newRPCommitFromFS generates a range proof commitment for a given integer
func newRPCommitFromFS(pp *PublicParameters, coins Int3, ts Int3) (cList Int3) {
	opt := iPool.Get().(*big.Int)
	defer iPool.Put(opt)
	for i := 0; i < int3Len; i++ {
		cList[i] = new(big.Int).Exp(pp.G, ts[i], pp.N)
		cList[i].Mul(cList[i], opt.Exp(pp.H, coins[i], pp.N))
	}
	return
}

// commit composes the commitment for range proof
func (r *RPProver) commit() (rpCommitment, error) {
	// pick m1, m2, m3, m4, mi is in [0, 2^(B + 2kappa)]
	powMLmt := iPool.Get().(*big.Int).Set(r.sp)
	defer iPool.Put(powMLmt)
	powMLmt.Lsh(powMLmt, 1)
	powMLmt.Add(powMLmt, rpB)
	mLmt := iPool.Get().(*big.Int).Exp(big2, powMLmt, nil)
	defer iPool.Put(mLmt)
	m4, err := newFourRandCoins(mLmt)
	if err != nil {
		return rpCommitment{}, err
	}
	r.randM4 = m4
	// pick s1, s2, s3, s4, si is in [0, 2^(2kappa)*n]
	sLmt := iPool.Get().(*big.Int).Exp(big4, r.sp, nil)
	defer iPool.Put(sLmt)
	sLmt.Mul(sLmt, r.pp.N)
	var s4 Int4
	if s4, err = newFourRandCoins(sLmt); err != nil {
		return rpCommitment{}, err
	}
	r.randS4 = s4
	// pick sigma in [0, 2^(B + 2kappa)*n]
	sLmt.Lsh(sLmt, uint(rpB.Int64()))
	var sigma *big.Int
	if sigma, err = freshRandCoin(sLmt); err != nil {
		return rpCommitment{}, err
	}
	r.sigma = sigma
	// calculate commitment
	d4 := firstPartH(r.pp, m4, s4)
	d := secondPartH(sigma, r.pp.H, r.pp.N, r.commitFSX, m4)
	c := newRPCommitment(d4, d)
	return c, nil
}

// firstPartH calculates h1, h2, h3, h4, hi = (g^mi)(h^si) mod n
func firstPartH(pp *PublicParameters, m, s Int4) Int4 {
	var h4 Int4
	opt := iPool.Get().(*big.Int)
	defer iPool.Put(opt)
	for i := 0; i < int4Len; i++ {
		h := new(big.Int).Set(pp.G)
		h.Exp(h, m[i], pp.N)
		h.Mul(h, opt.Exp(pp.H, s[i], pp.N))
		h4[i] = h.Mod(h, pp.N)
	}
	return h4
}

// secondPartH calculates h = (h^(sigma))*(c^(m0)_a)*(product of (ci^(-mi))) mod n
func secondPartH(sigma, h, n *big.Int, c Int3, m Int4) *big.Int {
	// prefix = h^sigma * c_
	prefix := iPool.Get().(*big.Int).Exp(h, sigma, n)
	defer iPool.Put(prefix)
	// ci^(-mi)
	var cPowM4 Int4
	opt := iPool.Get().(*big.Int)
	defer iPool.Put(opt)
	negM := iPool.Get().(*big.Int)
	defer iPool.Put(negM)
	for i := 0; i < int3Len; i++ {
		cPowM4[i] = opt.Exp(c[i], negM.Neg(m[i]), n)
	}
	// product of ci^(-mi)
	d := big.NewInt(1)
	for i := 0; i < 4; i++ {
		d.Mul(d, cPowM4[i])
		d.Mod(d, n)
	}
	d.Mul(d, prefix)
	d.Mod(d, n)
	return d
}

// calChallengeBigInt calculates the challenge for range proof in big integer format
func (r *RPProver) calChallengeBigInt() *big.Int {
	challenge := newRPChallenge(r.pp, r.commitFSX)
	return challenge.bigInt()
}

// response generates the response for verifier's challenge
func (r *RPProver) response() (*rpResponse, error) {
	c := r.calChallengeBigInt()
	var z4 Int4
	for i := 0; i < 4; i++ {
		z4[i] = new(big.Int).Mul(c, r.squareX3[i])
		z4[i].Add(z4[i], r.randM4[i])
	}
	var t4 Int4
	for i := 0; i < 4; i++ {
		t4[i] = new(big.Int).Mul(c, r.randR4[i])
		t4[i].Add(t4[i], r.randS4[i])
	}

	sumXR := iPool.Get().(*big.Int)
	defer iPool.Put(sumXR)
	sumXR.SetInt64(0)
	opt := iPool.Get().(*big.Int)
	defer iPool.Put(opt)
	for i := 0; i < 4; i++ {
		sumXR.Add(sumXR, opt.Mul(r.squareX3[i], r.randR4[i]))
	}
	t := new(big.Int).Sub(r.r, sumXR)
	t.Mul(t, c)
	t.Add(t, r.sigma)
	response := &rpResponse{
		Z4: z4,
		T4: t4,
		T:  t,
	}
	return response, nil
}

// RPVerifier refers to the Verifier in zero-knowledge integer range proof
type RPVerifier struct {
	pp         *PublicParameters // public parameters
	sp         *big.Int          // security parameters
	C          *big.Int          // C, (g^x)(h^r)
	commitment rpCommitment      // commitment, delta = H(d1, d2, d3, d4, d)
	commitFSX  Int4
}

// NewRPVerifier generates a new range proof verifier
func NewRPVerifier(pp *PublicParameters) *RPVerifier {
	verifier := &RPVerifier{
		pp: pp,
		sp: big.NewInt(securityParam),
	}
	return verifier
}

// Verify verifies the range proof
func (r *RPVerifier) Verify(proof *RangeProof) bool {
	r.SetC(proof.c)
	r.setCommitForX(proof.commitX)
	r.setCommitment(proof.commitment)
	return r.VerifyResponse(proof.response)
}

// SetC sets C to the verifier
func (r *RPVerifier) SetC(c *big.Int) {
	r.C = c
}

// setCommitment sets the commitment to the verifier
func (r *RPVerifier) setCommitment(c rpCommitment) {
	r.commitment = c
}

// setCommitForX sets the commitment of x to the verifier
// Commitment of x: c1, c2, c3, c4, ci = (g^x1=i)(h^ri)
func (r *RPVerifier) setCommitForX(c4 Int4) {
	r.commitFSX = c4
}

// challenge generates a challenge for prover's commitment
func (r *RPVerifier) challenge() *big.Int {
	challenge := newRPChallenge(r.pp, r.commitFSX)
	return challenge.bigInt()
}

// VerifyResponse verifies the response, if accepts, return true; otherwise, return false
func (r *RPVerifier) VerifyResponse(response *rpResponse) bool {
	c := r.challenge()
	// the first 4 parameters: (g^zi)(h^ti)(ci^(-e)) mod n
	var firstFourParams Int4
	negC := iPool.Get().(*big.Int).Neg(c)
	defer iPool.Put(negC)
	opt := iPool.Get().(*big.Int)
	defer iPool.Put(opt)
	for i := 0; i < 4; i++ {
		firstFourParams[i] = new(big.Int).Exp(r.pp.G, response.Z4[i], r.pp.N)
		firstFourParams[i].Mul(
			firstFourParams[i],
			opt.Exp(r.pp.H, response.T4[i], r.pp.N),
		)
		firstFourParams[i].Mul(
			firstFourParams[i],
			opt.Exp(r.commitFSX[i], negC, r.pp.N),
		)
		firstFourParams[i].Mod(firstFourParams[i], r.pp.N)
	}

	cPowNegE := iPool.Get().(*big.Int)
	defer iPool.Put(cPowNegE)
	cPowNegE.Exp(r.C, negC, r.pp.N) // c^(-e)
	hPowT := iPool.Get().(*big.Int)
	defer iPool.Put(hPowT)
	hPowT.Exp(r.pp.H, response.T, r.pp.N) // h^t
	//product of (ci^zi)(h^t)(c^(-e)) mod n
	prodParam := iPool.Get().(*big.Int)
	defer iPool.Put(prodParam)
	prodParam.SetInt64(1)
	for i := 0; i < 4; i++ {
		prodParam.Mul(
			prodParam,
			opt.Exp(r.commitFSX[i], response.Z4[i], r.pp.N),
		)
		prodParam.Mod(prodParam, r.pp.N)
	}
	prodParam.Mul(prodParam, hPowT)
	prodParam.Mod(prodParam, r.pp.N)
	prodParam.Mul(prodParam, cPowNegE)
	prodParam.Mod(prodParam, r.pp.N)

	hashF := sha256.New()
	var sha256List [4][]byte
	for i := 0; i < 4; i++ {
		hashF.Write(firstFourParams[i].Bytes())
		sha256List[i] = hashF.Sum(nil)
		hashF.Reset()
	}
	hashF.Write(prodParam.Bytes())
	h := hashF.Sum(nil)
	var commitment rpCommitment
	for i := 0; i < 4; i++ {
		copy(commitment[i*sha256Len:(i+1)*sha256Len], sha256List[i])
	}
	copy(commitment[commitLen-sha256Len:], h)
	return commitment == r.commitment
}
