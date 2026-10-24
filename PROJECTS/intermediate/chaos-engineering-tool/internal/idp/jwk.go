// ©AngelaMos | 2026
// jwk.go

package idp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
)

const (
	errNoSuchKid        = "%w: %q (published: %s)"
	errIncompleteJWK    = "%w: the key %q does not carry %s"
	errUnusableJWK      = "%w: the key %q carries material khaos will not build a verifier from"
	errUnsupportedCurve = "%w: the key %q is on curve %q and khaos only serves %s"
	kidSep              = ", "
)

var ErrNoSuchKey = errors.New("that key is not in the published JWK Set")

// JWK is the published form of one key. The `alg` member is deliberate:
// RFC 8725 rule 2 says a verifier MUST cross-check it against the header.
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`

	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func (s JWKSet) Kids() []string {
	out := make([]string, 0, len(s.Keys))
	for _, key := range s.Keys {
		out = append(out, key.Kid)
	}
	return out
}

func (s JWKSet) Has(kid string) bool {
	for _, key := range s.Keys {
		if key.Kid == kid {
			return true
		}
	}
	return false
}

func (s JWKSet) Lookup(kid string) (JWK, error) {
	for _, key := range s.Keys {
		if key.Kid == kid {
			return key, nil
		}
	}
	return JWK{}, fmt.Errorf(
		errNoSuchKid,
		ErrNoSuchKey,
		kid,
		joinKids(s.Kids()),
	)
}

func joinKids(kids []string) string {
	if len(kids) == 0 {
		return "nothing"
	}
	out := kids[0]
	for _, kid := range kids[1:] {
		out += kidSep + kid
	}
	return out
}

// PublicJWK is the published form. It is a superset of the members the
// thumbprint covers, so the two forms are built separately.
func (k *Key) PublicJWK() JWK {
	out := JWK{
		Kid: k.ID,
		Use: useSignature,
		Alg: string(k.Alg),
	}

	if k.rsaKey != nil {
		out.Kty = keyTypeRSA
		out.N = b64(k.rsaKey.N.Bytes())
		out.E = b64(exponentBytes(k.rsaKey.E))
		return out
	}

	name, size := curveShape(k.ecKey.Curve)
	x, y := coordinates(&k.ecKey.PublicKey, size)

	out.Kty = keyTypeEC
	out.Crv = name
	out.X = b64(x)
	out.Y = b64(y)

	return out
}

// RSAPublicKey rebuilds a verifiable key from a published JWK. Both guards are
// load-bearing: decodeBigInt("") yields zero with a nil error, and
// big.Int.Int64 is undefined on overflow, where 2^64 + 1 truncates to e = 1,
// the one exponent that makes the signature and the encoded message identical.
func (j JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if j.N == "" || j.E == "" {
		return nil, fmt.Errorf(errIncompleteJWK, ErrNoSuchKey, j.Kid, "n and e")
	}

	n, err := decodeBigInt(j.N)
	if err != nil {
		return nil, err
	}

	e, err := decodeBigInt(j.E)
	if err != nil {
		return nil, err
	}

	if n.Sign() <= 0 || !e.IsInt64() || e.Int64() < 3 ||
		e.Int64() > math.MaxInt32 {
		return nil, fmt.Errorf(errUnusableJWK, ErrNoSuchKey, j.Kid)
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// ECPublicKey rebuilds an EC key, and refuses a curve khaos does not serve.
func (j JWK) ECPublicKey() (*ecdsa.PublicKey, error) {
	if j.Crv != curveP256 {
		return nil, fmt.Errorf(
			errUnsupportedCurve,
			ErrNoSuchKey,
			j.Kid,
			j.Crv,
			curveP256,
		)
	}

	if j.X == "" || j.Y == "" {
		return nil, fmt.Errorf(errIncompleteJWK, ErrNoSuchKey, j.Kid, "x and y")
	}

	x, err := decodeBigInt(j.X)
	if err != nil {
		return nil, err
	}

	y, err := decodeBigInt(j.Y)
	if err != nil {
		return nil, err
	}

	if !p256().IsOnCurve(x, y) {
		return nil, fmt.Errorf(errUnusableJWK, ErrNoSuchKey, j.Kid)
	}

	return &ecdsa.PublicKey{Curve: p256(), X: x, Y: y}, nil
}

func decodeBigInt(encoded string) (*big.Int, error) {
	raw, err := decodeSegment(encoded)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func (s JWKSet) Encode() ([]byte, error) {
	return json.Marshal(s)
}

func ParseJWKSet(raw []byte) (JWKSet, error) {
	var set JWKSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return JWKSet{}, err
	}
	return set, nil
}

func bigFromBytes(raw []byte) *big.Int {
	return new(big.Int).SetBytes(raw)
}

// UseSignature is RFC 7517's `use` value for a signing key.
const UseSignature = useSignature
