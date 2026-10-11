// ©AngelaMos | 2026
// key.go

package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm is the JWS `alg` header value. khaos needs to mint tokens under
// algorithms a correct provider would refuse to use at all, so this is the set
// khaos can SIGN with rather than a set it endorses.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
	HS256 Algorithm = "HS256"

	// None is RFC 7515's "No digital signature or MAC performed". It exists here
	// because a verifier that routes on it is trap T1, and khaos cannot test for
	// that without being willing to emit it.
	None Algorithm = "none"
)

const (
	keyTypeRSA = "RSA"
	keyTypeEC  = "EC"

	curveP256 = "P-256"

	useSignature = "sig"

	// The modulus size khaos signs its honest tokens with. 2048 is what a real
	// provider uses and it is comfortably above the floor crypto/rsa enforces.
	strongBits = 2048

	// Deliberately below that floor. Measured on go1.26.5: crypto/rsa refuses a
	// key this size at GenerateKey, at SignPKCS1v15 AND at VerifyPKCS1v15, all
	// three through checkKeySize, so a token signed under it cannot be produced
	// or checked by the standard library at all. That is the whole point of the
	// weak-key probe, and it is why khaos carries its own PKCS#1 v1.5 path below.
	weakBits = 512

	// Each prime is half the modulus. Assembling the key by hand is what lets
	// khaos hold one crypto/rsa will not generate.
	weakPrimeBits = weakBits / 2

	// crypto/rsa's own floor, read from the source rather than remembered:
	// checkKeySize returns nil at or above this and an error below it unless the
	// rsa1024min GODEBUG is set. khaos never sets that GODEBUG, because doing so
	// to enable one probe would weaken every other thing khaos does with RSA.
	libraryFloorBits = 1024

	primeAttempts = 64

	// ES256 signatures are the fixed-width concatenation of r and s, each padded
	// to the curve's coordinate size. RFC 7518 section 3.4.
	p256CoordinateBytes = 32

	errNoPrime      = "khaos could not find a %d-bit prime for its deliberately weak signing key after %d attempts"
	errBadAlg       = "%w: %q"
	errNotRSA       = "%w: %s is not an RSA key, and %s is an RSA algorithm"
	errNotEC        = "%w: %s is not an EC key, and %s is an EC algorithm"
	errCoprime      = "khaos could not invert the public exponent against its chosen primes"
	errShortModulus = "the digest and PKCS#1 v1.5 framing need %d bytes and this key's modulus is only %d"
)

var ErrUnsupportedAlgorithm = errors.New(
	"khaos cannot sign under that algorithm",
)

var ErrKeyAlgorithmMismatch = errors.New(
	"that key cannot sign under that algorithm",
)

// Key is one signing key the provider publishes and signs with. The thumbprint
// is its `kid`, so a rotated key's identity is derived from the key material
// rather than from a counter khaos increments: two providers holding the same
// key agree on its name, and a `kid` cannot be reused for different bytes.
type Key struct {
	ID  string
	Alg Algorithm

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

// NewRSAKey mints a key a real provider would use.
func NewRSAKey() (*Key, error) {
	return newRSAKey(strongBits)
}

// NewWeakRSAKey mints a key below the size crypto/rsa will accept, by assembling
// the struct from primes khaos finds itself. Nothing in crypto/rsa validates a
// PrivateKey on construction, so the value is well-formed and usable right up to
// the moment a crypto/rsa function is called with it, which is exactly the
// position a verifier that reimplements RSA puts itself in.
func NewWeakRSAKey() (*Key, error) {
	key, err := weakRSAPrivateKey()
	if err != nil {
		return nil, err
	}
	return keyFromRSA(key)
}

func newRSAKey(bits int) (*Key, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return keyFromRSA(key)
}

func keyFromRSA(key *rsa.PrivateKey) (*Key, error) {
	out := &Key{Alg: RS256, rsaKey: key}

	id, err := out.Thumbprint()
	if err != nil {
		return nil, err
	}

	out.ID = id

	return out, nil
}

// NewECKey mints khaos's ES256 key. The curve is P-256 because ES256 is defined
// over it, and the surrounding code derives its widths from the curve rather
// than from that fact, so adding ES384 later is a constructor and not a hunt.
func NewECKey() (*Key, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	out := &Key{Alg: ES256, ecKey: key}

	id, err := out.Thumbprint()
	if err != nil {
		return nil, err
	}

	out.ID = id

	return out, nil
}

// Weak reports whether this key is below the size crypto/rsa accepts. It is
// derived from the modulus rather than remembered from construction, so a key
// cannot claim to be strong while carrying weak material.
func (k *Key) Weak() bool {
	return k.rsaKey != nil && k.rsaKey.N.BitLen() < libraryFloorBits
}

// PublicDER is the SPKI encoding of the public key. It is what the algorithm
// confusion probe uses as its HMAC secret, because an RSA public key loaded from
// a PEM file is these bytes and a verifier that hands them to an HMAC function
// is trap T2.
func (k *Key) PublicDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.public())
}

func (k *Key) public() crypto.PublicKey {
	if k.rsaKey != nil {
		return &k.rsaKey.PublicKey
	}
	return &k.ecKey.PublicKey
}

// Sign produces the JWS signature over the signing input. It refuses an
// algorithm the key cannot carry rather than silently producing a signature
// nothing can check, because a probe that fails for the wrong reason reads
// exactly like a target that refused it.
func (k *Key) Sign(alg Algorithm, signingInput []byte) ([]byte, error) {
	switch alg {
	case RS256:
		if k.rsaKey == nil {
			return nil, fmt.Errorf(
				errNotRSA,
				ErrKeyAlgorithmMismatch,
				k.ID,
				alg,
			)
		}
		return k.signRSA(signingInput)
	case ES256:
		if k.ecKey == nil {
			return nil, fmt.Errorf(errNotEC, ErrKeyAlgorithmMismatch, k.ID, alg)
		}
		return k.signEC(signingInput)
	default:
		return nil, fmt.Errorf(errBadAlg, ErrUnsupportedAlgorithm, alg)
	}
}

// signRSA uses the standard library wherever the standard library will accept
// the key, and khaos's own PKCS#1 v1.5 path only where it will not. The two are
// pinned to agree byte for byte at a legal key size, so the weak-key path is
// exercised against a known-good reference rather than trusted on its own.
func (k *Key) signRSA(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)

	if !k.Weak() {
		return rsa.SignPKCS1v15(rand.Reader, k.rsaKey, crypto.SHA256, digest[:])
	}

	return signPKCS1v15Raw(k.rsaKey, digest[:])
}

func (k *Key) signEC(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)

	r, s, err := ecdsa.Sign(rand.Reader, k.ecKey, digest[:])
	if err != nil {
		return nil, err
	}

	out := make([]byte, 2*p256CoordinateBytes)
	r.FillBytes(out[:p256CoordinateBytes])
	s.FillBytes(out[p256CoordinateBytes:])

	return out, nil
}

// Thumbprint is the RFC 7638 JWK thumbprint: the required members only, in
// lexicographic order, with no whitespace, SHA-256, base64url with no padding.
// It is implemented from the specification text and pinned by the worked example
// in RFC 7638 section 3.1.
func (k *Key) Thumbprint() (string, error) {
	canonical, err := k.canonicalJWK()
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(canonical)

	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func (k *Key) canonicalJWK() ([]byte, error) {
	if k.rsaKey != nil {
		return canonicalRSAJWK(&k.rsaKey.PublicKey), nil
	}
	if k.ecKey != nil {
		return canonicalECJWK(&k.ecKey.PublicKey), nil
	}
	return nil, fmt.Errorf(errBadAlg, ErrUnsupportedAlgorithm, k.Alg)
}

// canonicalRSAJWK is the required-members-only RSA form. The member order is
// e, kty, n, which is lexicographic, and it is written literally rather than
// marshalled, because encoding/json orders struct fields by declaration and a
// field reorder would silently change every kid khaos derives.
func canonicalRSAJWK(pub *rsa.PublicKey) []byte {
	return []byte(fmt.Sprintf(
		`{"e":%q,"kty":%q,"n":%q}`,
		b64(exponentBytes(pub.E)),
		keyTypeRSA,
		b64(pub.N.Bytes()),
	))
}

// exponentBytes is the base64url-ready form of the public exponent: big-endian,
// with no leading zero octets. RFC 7518 section 6.3.1.2 calls for the
// "base64urlUInt-encoded value", and a leading zero would change the thumbprint
// for the same key.
func exponentBytes(e int) []byte {
	return new(big.Int).SetInt64(int64(e)).Bytes()
}

// canonicalECJWK is the required-members-only EC form, in the lexicographic
// order crv, kty, x, y.
func canonicalECJWK(pub *ecdsa.PublicKey) []byte {
	name, size := curveShape(pub.Curve)
	x, y := coordinates(pub, size)

	return []byte(fmt.Sprintf(
		`{"crv":%q,"kty":%q,"x":%q,"y":%q}`,
		name,
		keyTypeEC,
		b64(x),
		b64(y),
	))
}

// curveShape is the curve's JWK name and its coordinate width, DERIVED from the
// curve rather than hardcoded.
//
// Hardcoding P-256 in three places made a larger curve PANIC inside the `jwks`
// HTTP handler — math/big's FillBytes refuses a buffer too small for the value —
// and made a smaller one serialize as a zero-padded 28-byte coordinate labelled
// P-256, which is a different key under a different thumbprint. Neither was
// reachable through NewECKey, which is why neither was noticed.
func curveShape(curve elliptic.Curve) (string, int) {
	switch curve {
	case elliptic.P384():
		return "P-384", 48
	case elliptic.P521():
		return "P-521", 66
	default:
		return curveP256, p256CoordinateBytes
	}
}

// coordinates is the fixed-width big-endian pair RFC 7518 section 6.2.1.2 calls
// for. The width comes from the curve, so a short coordinate is padded and a
// long one cannot overflow the buffer.
func coordinates(pub *ecdsa.PublicKey, size int) ([]byte, []byte) {
	x := make([]byte, size)
	y := make([]byte, size)

	if pub.X.BitLen() > size*8 || pub.Y.BitLen() > size*8 {
		return x, y
	}

	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)

	return x, y
}

func b64(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// weakRSAPrivateKey assembles a key crypto/rsa will not generate. It is built
// the long way round rather than with GenerateKey because GenerateKey enforces
// the same floor as the signing and verifying paths.
func weakRSAPrivateKey() (*rsa.PrivateKey, error) {
	exponent := big.NewInt(defaultExponent)

	for range primeAttempts {
		p, err := rand.Prime(rand.Reader, weakPrimeBits)
		if err != nil {
			return nil, err
		}

		q, err := rand.Prime(rand.Reader, weakPrimeBits)
		if err != nil {
			return nil, err
		}

		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		if n.BitLen() != weakBits {
			continue
		}

		// Carmichael's totient, which is what PKCS#1 actually requires. Using
		// Euler's would also work but produces a larger private exponent for no
		// benefit.
		pMinus := new(big.Int).Sub(p, one)
		qMinus := new(big.Int).Sub(q, one)
		totient := new(
			big.Int,
		).Div(new(big.Int).Mul(pMinus, qMinus), new(big.Int).GCD(nil, nil, pMinus, qMinus))

		d := new(big.Int).ModInverse(exponent, totient)
		if d == nil {
			continue
		}

		key := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: defaultExponent},
			D:         d,
			Primes:    []*big.Int{p, q},
		}

		key.Precompute()

		return key, nil
	}

	return nil, fmt.Errorf(errNoPrime, weakPrimeBits, primeAttempts)
}

const defaultExponent = 65537

var one = big.NewInt(1)

// sha256DigestInfo is the DER-encoded DigestInfo prefix for SHA-256, from
// RFC 8017 section 9.2 note 1. PKCS#1 v1.5 signs this prefix followed by the
// digest, so the value is fixed and not computed.
var sha256DigestInfo = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
	0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

// signPKCS1v15Raw is RFC 8017's RSASSA-PKCS1-v1_5 over a modulus crypto/rsa
// refuses to touch. It exists for exactly one probe and it is pinned against
// rsa.SignPKCS1v15 at a legal key size, so the arithmetic is verified against
// the standard library rather than asserted.
//
// There is no constant-time concern here: the key is a throwaway khaos generated
// to be weak on purpose, published in khaos's own JWK Set, and discarded with the
// run.
func signPKCS1v15Raw(key *rsa.PrivateKey, digest []byte) ([]byte, error) {
	size := (key.N.BitLen() + 7) / 8
	framed := len(sha256DigestInfo) + len(digest)

	// EM = 0x00 || 0x01 || PS || 0x00 || T, and PS must be at least 8 bytes.
	if size < framed+11 {
		return nil, fmt.Errorf(errShortModulus, framed+11, size)
	}

	block := make([]byte, size)
	block[0] = 0x00
	block[1] = 0x01
	for i := 2; i < size-framed-1; i++ {
		block[i] = 0xff
	}
	block[size-framed-1] = 0x00
	copy(block[size-framed:], sha256DigestInfo)
	copy(block[size-len(digest):], digest)

	m := new(big.Int).SetBytes(block)
	c := new(big.Int).Exp(m, key.D, key.N)

	out := make([]byte, size)
	c.FillBytes(out)

	return out, nil
}

// verifyPKCS1v15Raw is the mirror, and it is here rather than in the range
// fixture because the confirmation oracle needs it: khaos has to be able to
// prove the token it just minted really does verify under the weak key it
// published, or "the target accepted it" says nothing about what khaos sent.
func verifyPKCS1v15Raw(pub *rsa.PublicKey, digest, signature []byte) bool {
	// The exponent is validated because this function is EXPORTED with a comment
	// inviting reuse, and a caller who built the key from an attacker-supplied
	// JWK can hand it anything.
	//
	// Measured: with e = 1 the modular exponentiation is the identity, so the
	// signature IS the encoded message and khaos accepted a forgery that
	// rsa.VerifyPKCS1v15 refused. The standard library's FIPS path rejects e < 2
	// and even exponents; this path rejected neither. An `"e":"AQAAAAAAAAAB"`
	// (2^64+1) also truncated to 1 through big.Int.Int64, whose behaviour is
	// documented as undefined on overflow.
	if pub.N == nil || pub.E < 3 || pub.E%2 == 0 {
		return false
	}

	size := (pub.N.BitLen() + 7) / 8
	if len(signature) != size {
		return false
	}

	c := new(big.Int).SetBytes(signature)
	if c.Cmp(pub.N) >= 0 {
		return false
	}

	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)

	block := make([]byte, size)
	m.FillBytes(block)

	framed := len(sha256DigestInfo) + len(digest)
	if size < framed+11 {
		return false
	}

	if block[0] != 0x00 || block[1] != 0x01 || block[size-framed-1] != 0x00 {
		return false
	}

	for i := 2; i < size-framed-1; i++ {
		if block[i] != 0xff {
			return false
		}
	}

	expected := make([]byte, 0, framed)
	expected = append(expected, sha256DigestInfo...)
	expected = append(expected, digest...)

	for i := range expected {
		if block[size-framed+i] != expected[i] {
			return false
		}
	}

	return true
}

// VerifyPKCS1v15Raw is khaos's own PKCS#1 v1.5 verification, exported for the
// range's reference verifier. The fixture needs it to express the one bug Go's
// standard library makes unreachable: crypto/rsa enforces a 1024-bit floor, so a
// verifier that accepts an undersized key has to have reimplemented RSA, which
// is what most libraries in other ecosystems have done.
//
// It is pinned against rsa.SignPKCS1v15 at a legal key size by this package's
// own tests, in both directions.
func VerifyPKCS1v15Raw(pub *rsa.PublicKey, digest, signature []byte) bool {
	return verifyPKCS1v15Raw(pub, digest, signature)
}

// SPKIPEMBytes is the serialization a verifier is overwhelmingly holding when it
// was handed "the issuer's public key": a PEM file read off disk. It is exported
// because the algorithm-confusion bug is only reachable when the forged MAC and
// the verifier's secret are the SAME bytes, so khaos and the fixture have to
// agree on which bytes those are.
func SPKIPEMBytes(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: der}), nil
}
