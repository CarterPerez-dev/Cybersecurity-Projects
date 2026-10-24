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

// Algorithm is a JWS `alg` khaos can SIGN with, not one it endorses.
type Algorithm string

const (
	RS256 Algorithm = "RS256"
	ES256 Algorithm = "ES256"
	HS256 Algorithm = "HS256"

	None Algorithm = "none"
)

const (
	keyTypeRSA = "RSA"
	keyTypeEC  = "EC"

	curveP256 = "P-256"

	useSignature = "sig"

	strongBits = 2048

	// Below crypto/rsa's floor, which refuses a key this size at GenerateKey,
	// at SignPKCS1v15 and at VerifyPKCS1v15 alike, hence the raw path below.
	weakBits = 512

	weakPrimeBits = weakBits / 2

	// crypto/rsa's floor, waived only by the rsa1024min GODEBUG khaos never sets.
	libraryFloorBits = 1024

	primeAttempts = 64

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

// Key is one signing key, whose RFC 7638 thumbprint is its `kid`.
type Key struct {
	ID  string
	Alg Algorithm

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
}

func NewRSAKey() (*Key, error) {
	return newRSAKey(strongBits)
}

// Built by hand: crypto/rsa validates no PrivateKey on construction.
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

func (k *Key) Weak() bool {
	return k.rsaKey != nil && k.rsaKey.N.BitLen() < libraryFloorBits
}

func (k *Key) PublicDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.public())
}

func (k *Key) public() crypto.PublicKey {
	if k.rsaKey != nil {
		return &k.rsaKey.PublicKey
	}
	return &k.ecKey.PublicKey
}

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

// Thumbprint is the RFC 7638 JWK thumbprint, which khaos uses as the `kid`.
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

// Written literally rather than marshalled, because encoding/json orders
// fields by declaration and a reorder would change every kid khaos derives.
func canonicalRSAJWK(pub *rsa.PublicKey) []byte {
	return []byte(fmt.Sprintf(
		`{"e":%q,"kty":%q,"n":%q}`,
		b64(exponentBytes(pub.E)),
		keyTypeRSA,
		b64(pub.N.Bytes()),
	))
}

// Big-endian with no leading zero octets, which would change the thumbprint.
func exponentBytes(e int) []byte {
	return new(big.Int).SetInt64(int64(e)).Bytes()
}

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

// Derived from the curve rather than hardcoded: FillBytes panics on a buffer
// too small, and a padded short coordinate is a different key.
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

// RFC 8017's DER DigestInfo prefix for SHA-256: fixed, not computed.
var sha256DigestInfo = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
	0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

// RFC 8017's RSASSA-PKCS1-v1_5 over a modulus crypto/rsa refuses. No
// constant-time concern: the key is a throwaway, weak on purpose.
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

func verifyPKCS1v15Raw(pub *rsa.PublicKey, digest, signature []byte) bool {
	// Load-bearing: with e = 1 the exponentiation is the identity, so the
	// signature IS the encoded message. crypto/rsa's FIPS path rejects e < 2.
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

// VerifyPKCS1v15Raw verifies under a modulus crypto/rsa refuses to touch.
func VerifyPKCS1v15Raw(pub *rsa.PublicKey, digest, signature []byte) bool {
	return verifyPKCS1v15Raw(pub, digest, signature)
}

// The bytes a verifier handed "the issuer's public key" is usually holding.
func SPKIPEMBytes(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublic, Bytes: der}), nil
}
