// ©AngelaMos | 2026
// token.go

package idp

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	segmentSep   = "."
	jwsSegments  = 3
	typJWT       = "JWT"
	typAccessJWT = "at+jwt"

	errSegments = "%w: a JWS has %d dot-separated segments and this has %d"
	errSegment  = "%w: segment %d is not base64url (%v)"
	errHeader   = "%w: the header segment is not JSON (%v)"
	errClaims   = "%w: the claims segment is not JSON (%v)"
)

var ErrNotAJWS = errors.New("that is not a JWS compact serialization")

// Header carries the fields a correct provider never sets, and `alg` is a
// plain string so khaos can emit a value it does not itself support.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`

	// JWK is RFC 7515's in-token key. A verifier that resolves a key from here
	// rather than from the trusted set has violated RFC 8725 rule 4.
	JWK *JWK `json:"jwk,omitempty"`

	// JKU is the in-token key-set URL, and khaos does not set it. The field
	// stays so non-following can be expressed without reshaping the header.
	JKU string `json:"jku,omitempty"`
}

// Audience is RFC 7519 section 4.1.3's `aud`: an array of case-sensitive
// strings, which MAY be a single string when there is one audience.
type Audience []string

func (a *Audience) UnmarshalJSON(raw []byte) error {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		*a = Audience{one}
		return nil
	}

	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}

	*a = many

	return nil
}

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a Audience) Contains(want string) bool {
	for _, each := range a {
		if each == want {
			return true
		}
	}
	return false
}

func (a Audience) String() string {
	return strings.Join(a, ", ")
}

// Claims keeps every time field as a pointer, so khaos can emit a claim that
// is genuinely ABSENT rather than present and zero.
type Claims struct {
	Issuer    string   `json:"iss,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	Expires   *int64   `json:"exp,omitempty"`
	NotBefore *int64   `json:"nbf,omitempty"`
	IssuedAt  *int64   `json:"iat,omitempty"`
	ID        string   `json:"jti,omitempty"`
	Scope     string   `json:"scope,omitempty"`
}

// Token keeps its segments verbatim: a signature is over the bytes as sent.
type Token struct {
	Raw          string
	SigningInput []byte
	Header       Header
	Claims       Claims
	Signature    []byte
	HeaderJSON   []byte
	ClaimsJSON   []byte
}

func assemble(headerJSON, claimsJSON, signature []byte) string {
	return b64(
		headerJSON,
	) + segmentSep + b64(
		claimsJSON,
	) + segmentSep + b64(
		signature,
	)
}

func signingInput(headerJSON, claimsJSON []byte) []byte {
	return []byte(b64(headerJSON) + segmentSep + b64(claimsJSON))
}

func Parse(raw string) (Token, error) {
	parts := strings.Split(raw, segmentSep)
	if len(parts) != jwsSegments {
		return Token{}, fmt.Errorf(
			errSegments,
			ErrNotAJWS,
			jwsSegments,
			len(parts),
		)
	}

	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return Token{}, fmt.Errorf(errSegment, ErrNotAJWS, 1, err)
	}

	claimsJSON, err := decodeSegment(parts[1])
	if err != nil {
		return Token{}, fmt.Errorf(errSegment, ErrNotAJWS, 2, err)
	}

	signature, err := decodeSegment(parts[2])
	if err != nil {
		return Token{}, fmt.Errorf(errSegment, ErrNotAJWS, 3, err)
	}

	out := Token{
		Raw:          raw,
		SigningInput: []byte(parts[0] + segmentSep + parts[1]),
		Signature:    signature,
		HeaderJSON:   headerJSON,
		ClaimsJSON:   claimsJSON,
	}

	if err := json.Unmarshal(headerJSON, &out.Header); err != nil {
		return Token{}, fmt.Errorf(errHeader, ErrNotAJWS, err)
	}

	if err := json.Unmarshal(claimsJSON, &out.Claims); err != nil {
		return Token{}, fmt.Errorf(errClaims, ErrNotAJWS, err)
	}

	return out, nil
}

// Strict base64url with no padding, per RFC 7515 section 2: a lenient decoder
// would read a token a verifier rejects for a different reason.
func decodeSegment(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}

func p256() elliptic.Curve {
	return elliptic.P256()
}

func unix(t time.Time) *int64 {
	seconds := t.Unix()
	return &seconds
}

// Retarget rewrites only the `kid`, so the intact signature stops verifying.
func Retarget(token Token, kid string) string {
	header := token.Header
	header.Kid = kid

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return token.Raw
	}

	return assemble(headerJSON, token.ClaimsJSON, token.Signature)
}

// LooksLikeJWS tests the SHAPE, because choosing on "did my parser succeed"
// makes a verifier whose `aud` field is a plain string reject a legal array one
// and then introspect it as though it were opaque.
func LooksLikeJWS(credential string) bool {
	parts := strings.Split(credential, segmentSep)
	if len(parts) != jwsSegments {
		return false
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return false
	}

	var probe struct {
		Alg string `json:"alg"`
	}

	if err := json.Unmarshal(header, &probe); err != nil {
		return false
	}

	return probe.Alg != ""
}

func Retyped(p *Provider, typ string) string {
	return p.reheader(func(header *Header) { header.Typ = typ })
}

func WithoutExpiry(p *Provider) string {
	return p.reclaim(func(claims *Claims) { claims.Expires = nil })
}
