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

// Header is the JOSE header khaos emits. Every field a trap needs to corrupt is
// here, including the ones a correct provider never sets: `jwk` exists so khaos
// can embed an attacker key, which is trap T2b, and `alg` is a plain string
// rather than an Algorithm so khaos can emit a value it does not itself support.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`

	// JWK is RFC 7515's in-token key. khaos sets it only for the key-injection
	// probe. A verifier that resolves a key from here instead of from the trusted
	// JWK Set has violated RFC 8725 rule 4, and that is the finding.
	JWK *JWK `json:"jwk,omitempty"`

	// JKU is the in-token key-set URL, and khaos does not set it.
	//
	// An earlier comment here claimed khaos pointed it at its own provider and
	// counted the hit. It did not: nothing in the repository ever assigned this
	// field. Research 07's trap T2b does ask for that probe — a verifier that
	// FETCHES an attacker-supplied URL is a finding even when the token is then
	// rejected — but the fetch is not an outcome in any probe stream, so
	// surfacing it needs an observation channel khaos does not have. The
	// omission is recorded in the design contract's fault catalogue rather than
	// described here as a feature.
	//
	// The field stays so a verifier's non-following of it is a property khaos can
	// express later without reshaping the header.
	JKU string `json:"jku,omitempty"`
}

// Claims is the payload. Every time field is a pointer so khaos can emit a token
// with a claim genuinely ABSENT rather than present and zero: a verifier that
// rejects `exp: 0` while accepting a missing `exp` is a different bug, and
// encoding/json cannot express the difference without this.
// Audience is RFC 7519 section 4.1.3's `aud`, which is "an array of
// case-sensitive strings" in the general case and "MAY be a single
// case-sensitive string" when there is one audience.
//
// It is a type rather than a plain string because a plain string made the
// general case fail to unmarshal, and a verifier that dispatched on parse
// success then treated a perfectly legal multi-audience JWT as an opaque
// credential.
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

// MarshalJSON emits the single-string form for one audience, because that is
// what a real provider emits and khaos's forged tokens have to be ordinary in
// every respect except the one property each trap corrupts.
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

// Token is a parsed JWS with its segments kept verbatim. The raw signing input
// is retained because re-deriving it from the decoded parts would re-serialize
// the JSON, and a signature is over the bytes that were actually sent.
type Token struct {
	Raw          string
	SigningInput []byte
	Header       Header
	Claims       Claims
	Signature    []byte
	HeaderJSON   []byte
	ClaimsJSON   []byte
}

// assemble builds the compact serialization. It takes the already-marshalled
// header and claims so a trap can corrupt either one before signing, and it
// takes the signature as bytes so a trap can replace it after signing.
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

// Parse reads a compact JWS without verifying anything. khaos uses it on its own
// confirmation path, where the question is what khaos actually emitted rather
// than whether it is acceptable.
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

// decodeSegment is strict base64url with no padding, which is what RFC 7515
// section 2 specifies. A lenient decoder would let khaos's own confirmation read
// a token a verifier would reject for a different reason.
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

// Retarget rewrites a token's `kid` and nothing else, leaving its signature
// intact and therefore unverifiable under the key it now names.
//
// It exists for the range verifier's own tests rather than for any khaos
// experiment: a header that disagrees with its key about the algorithm is
// forbidden by RFC 8725 rule 2, and no token an attacker could actually forge
// isolates that rule, because anything that trips it also fails the signature
// check. The fixture still has to carry the rule, so the rule still has to be
// exercised.
func Retarget(token Token, kid string) string {
	header := token.Header
	header.Kid = kid

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return token.Raw
	}

	return assemble(headerJSON, token.ClaimsJSON, token.Signature)
}

// LooksLikeJWS reports whether a credential has the SHAPE of a compact JWS:
// three dot-separated segments whose first decodes to JSON with an `alg`.
//
// A verifier has to choose between local validation and introspection before it
// can parse anything, and choosing on "did my parser succeed" is wrong in a way
// that matters: a token carrying a legal array `aud` fails a parser whose field
// is a string, and would then be introspected as though it were opaque.
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

// Retyped re-mints an honest token with a different `typ` and a valid signature.
// It exists so the range verifier's explicit-typing check can be exercised: a
// token whose signature does not verify would be refused before the claim checks
// are reached, and the typ check sits among them.
func Retyped(p *Provider, typ string) string {
	return p.reheader(func(header *Header) { header.Typ = typ })
}

// WithoutExpiry re-mints an honest token with no `exp` member at all, correctly
// signed. The pointer field is what makes an ABSENT claim expressible rather
// than a present zero.
func WithoutExpiry(p *Provider) string {
	return p.reclaim(func(claims *Claims) { claims.Expires = nil })
}
