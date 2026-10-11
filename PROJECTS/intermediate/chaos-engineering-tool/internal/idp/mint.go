// ©AngelaMos | 2026
// mint.go

package idp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// KeyForm is how a verifier loaded the issuer's public key, which decides what
// bytes the algorithm-confusion attack has to use as its HMAC secret. Research 07
// is explicit that this varies by target and that khaos should be able to try
// each, because the same bug is unreachable under the wrong serialization.
type KeyForm string

const (
	// SPKIPEM is the default because it is overwhelmingly how an RSA public key
	// reaches a verifier: a `.pem` file read off disk and passed through as a
	// string.
	SPKIPEM  KeyForm = "spki-pem"
	SPKIDER  KeyForm = "spki-der"
	PKCS1PEM KeyForm = "pkcs1-pem"

	// Modulus is the raw big-endian modulus, which is what a verifier that
	// reconstructed the key from the JWK's `n` member is holding.
	Modulus KeyForm = "modulus"
)

const (
	pemTypePublic    = "PUBLIC KEY"
	pemTypeRSAPublic = "RSA PUBLIC KEY"

	truncatedLength = 1

	errUnknownKeyForm   = "%w: %q (known forms: %s, %s, %s, %s)"
	errNoKey            = "%w: khaos's identity provider holds no %s key"
	errNothingToCorrupt = "%w: that token has no signature to corrupt"
)

var ErrUnknownKeyForm = errors.New(
	"khaos cannot serialize a public key that way",
)

var ErrNoSigningKey = errors.New(
	"khaos's identity provider is missing a key a trap needs",
)

func KeyForms() []string {
	return []string{
		string(SPKIPEM),
		string(SPKIDER),
		string(PKCS1PEM),
		string(Modulus),
	}
}

// grantRequest is what a token is minted for. The provider fills it from its own
// configuration so a caller never chooses the issuer or audience: a probe that
// could pick its own `aud` would make the wrong-audience trap meaningless.
type grantRequest struct {
	subject  string
	lifetime time.Duration
}

// mintToken produces one credential under the currently armed trap. Every branch
// corrupts EXACTLY ONE property and leaves the rest correct, which is what makes
// a 2xx isolate a single missing check rather than report that something,
// somewhere, is wrong.
//
// `typ` is the property that keeps each trap isolated: every token khaos mints
// carries `at+jwt`, including the forged ones, so a verifier that implements
// RFC 8725 section 3.11's explicit typing refuses each forgery for its OWN
// defect rather than for its type. Setting `typ: JWT` on the three header traps,
// which is what a careless forger would do, would get them refused on the type
// instead, and a token rejected for the wrong reason reads exactly like a target
// that caught the trap.
//
// An earlier version of this comment claimed that refusal had been OBSERVED. It
// had not: the explicit-typing check did not exist anywhere in the repository at
// the time, so the property this defends was inert against khaos's own fixture
// and the comment described a measurement nobody took. The check is now
// implemented in internal/verifier and `TestEveryTrapIsCaught...` exercises it.
func (p *Provider) mintToken(trap Trap, request grantRequest) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.clock()

	header := Header{Alg: string(RS256), Typ: typAccessJWT, Kid: p.signing.ID}
	claims := Claims{
		Issuer:    p.issuer,
		Subject:   request.subject,
		Audience:  Audience{p.audience},
		Expires:   unix(now.Add(request.lifetime)),
		NotBefore: unix(now),
		IssuedAt:  unix(now),
		ID:        rand.Text(),
	}

	// The same three groups the confirmations in observe.go use, so a reader can
	// put the mint and the observe for one group side by side. Each corrupts
	// exactly ONE property and leaves the rest internally consistent, because a
	// token that trips two checks isolates neither.
	switch trap.Kind {
	case AlgNone, AlgConfusion, EmbeddedJWK:
		return p.mintHeaderTrap(trap, header, claims)

	case ClaimExpired, ClaimNotYetValid, ClaimWrongAudience,
		ClaimForeignIssuer:
		return p.mintClaimTrap(trap, header, claims, now, request.lifetime)

	case SignatureTruncated, SignatureZero, SignatureWeakKey:
		return p.mintSignatureTrap(trap, header, claims)

	default:
		// The endpoint and key-state traps are expressed by the provider's own
		// behaviour rather than by the token, so an HONEST token is the correct
		// output for every one of them.
		return p.serialize(header, claims, nil, nil)
	}
}

// mintHeaderTrap corrupts the JOSE header and nothing else.
//
// This and its two siblings run under the read lock mintToken already holds, so
// none of them may take it again.
func (p *Provider) mintHeaderTrap(
	trap Trap,
	header Header,
	claims Claims,
) (string, error) {
	switch trap.Kind {
	case AlgNone:
		header.Alg = string(None)
		return p.serialize(header, claims, nil, nil)

	case AlgConfusion:
		header.Alg = string(HS256)
		secret, err := publicKeyBytes(p.signing, trap.KeyForm)
		if err != nil {
			return "", err
		}
		return p.serialize(
			header,
			claims,
			nil,
			func(input []byte) ([]byte, error) {
				mac := hmac.New(sha256.New, secret)
				mac.Write(input)
				return mac.Sum(nil), nil
			},
		)

	case EmbeddedJWK:
		if p.attacker == nil {
			return "", fmt.Errorf(errNoKey, ErrNoSigningKey, "attacker")
		}
		embedded := p.attacker.PublicJWK()
		header.Kid = p.attacker.ID
		header.JWK = &embedded
		return p.serialize(header, claims, p.attacker, nil)

	default:
		// Unreachable: mintToken routes only the header group here.
		return p.serialize(header, claims, nil, nil)
	}
}

// mintClaimTrap moves exactly one registered claim and leaves the signature
// valid, so a refusal can only have come from claim validation.
func (p *Provider) mintClaimTrap(
	trap Trap,
	header Header,
	claims Claims,
	now time.Time,
	lifetime time.Duration,
) (string, error) {
	switch trap.Kind {
	case ClaimExpired:
		// Internally consistent on purpose: the token is expired and nothing
		// else. A token that was also not-yet-valid would trip two checks and
		// isolate neither.
		claims.IssuedAt = unix(now.Add(-trap.Delay - lifetime))
		claims.NotBefore = unix(now.Add(-trap.Delay - lifetime))
		claims.Expires = unix(now.Add(-trap.Delay))
		return p.serialize(header, claims, nil, nil)

	case ClaimNotYetValid:
		claims.NotBefore = unix(now.Add(trap.Delay))
		claims.Expires = unix(now.Add(trap.Delay + lifetime))
		return p.serialize(header, claims, nil, nil)

	case ClaimWrongAudience:
		claims.Audience = Audience{p.foreignAudience}
		return p.serialize(header, claims, nil, nil)

	case ClaimForeignIssuer:
		// Signed by a key khaos DOES publish, in the same JWK Set. That is the
		// multi-tenant shape, and the teaching point is that the key set is not
		// the trust boundary: the signature verifies and only the `iss` check
		// can refuse it.
		if p.foreign == nil {
			return "", fmt.Errorf(errNoKey, ErrNoSigningKey, "second issuer")
		}
		claims.Issuer = p.foreignIssuer
		header.Kid = p.foreign.ID
		return p.serialize(header, claims, p.foreign, nil)

	default:
		// Unreachable: mintToken routes only the claim group here.
		return p.serialize(header, claims, nil, nil)
	}
}

// mintSignatureTrap corrupts the signature and leaves the header and every
// claim honest, so a refusal can only have come from signature verification.
func (p *Provider) mintSignatureTrap(
	trap Trap,
	header Header,
	claims Claims,
) (string, error) {
	switch trap.Kind {
	case SignatureTruncated:
		return p.serializeThen(
			header,
			claims,
			nil,
			func(signature []byte) []byte {
				return signature[:truncatedLength]
			},
		)

	case SignatureZero:
		if p.ec == nil {
			return "", fmt.Errorf(errNoKey, ErrNoSigningKey, "EC")
		}
		header.Alg = string(ES256)
		header.Kid = p.ec.ID
		return p.serializeThen(header, claims, p.ec, func([]byte) []byte {
			return make([]byte, 2*p256CoordinateBytes)
		})

	case SignatureWeakKey:
		if p.weak == nil {
			return "", fmt.Errorf(errNoKey, ErrNoSigningKey, "weak RSA")
		}
		header.Kid = p.weak.ID
		return p.serialize(header, claims, p.weak, nil)

	default:
		// Unreachable: mintToken routes only the signature group here.
		return p.serialize(header, claims, nil, nil)
	}
}

// serialize marshals, signs and assembles. A nil key means the provider's
// current signing key; a nil signer means the key's own algorithm.
func (p *Provider) serialize(
	header Header,
	claims Claims,
	key *Key,
	signer func([]byte) ([]byte, error),
) (string, error) {
	return p.serializeWith(header, claims, key, signer, nil)
}

func (p *Provider) serializeThen(
	header Header,
	claims Claims,
	key *Key,
	corrupt func([]byte) []byte,
) (string, error) {
	return p.serializeWith(header, claims, key, nil, corrupt)
}

func (p *Provider) serializeWith(
	header Header,
	claims Claims,
	key *Key,
	signer func([]byte) ([]byte, error),
	corrupt func([]byte) []byte,
) (string, error) {
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	input := signingInput(headerJSON, claimsJSON)

	signature, err := p.produceSignature(
		Algorithm(header.Alg),
		input,
		key,
		signer,
	)
	if err != nil {
		return "", err
	}

	if corrupt != nil {
		signature = corrupt(signature)
	}

	return assemble(headerJSON, claimsJSON, signature), nil
}

func (p *Provider) produceSignature(
	alg Algorithm,
	input []byte,
	key *Key,
	signer func([]byte) ([]byte, error),
) ([]byte, error) {
	if signer != nil {
		return signer(input)
	}

	if alg == None {
		return nil, nil
	}

	if key == nil {
		key = p.signing
	}

	return key.Sign(alg, input)
}

// publicKeyBytes is the bytes a verifier is holding for this key, under one of
// the four serializations research 07 says to try. It is the HMAC secret for the
// algorithm-confusion probe, and it is the whole reason that probe needs a
// parameter: the bug is unreachable if khaos guesses the wrong form.
func publicKeyBytes(key *Key, form KeyForm) ([]byte, error) {
	der, err := key.PublicDER()
	if err != nil {
		return nil, err
	}

	switch form {
	case SPKIDER:
		return der, nil

	case SPKIPEM:
		return pem.EncodeToMemory(
			&pem.Block{Type: pemTypePublic, Bytes: der},
		), nil

	case PKCS1PEM:
		if key.rsaKey == nil {
			return nil, fmt.Errorf(errNoKey, ErrNoSigningKey, "RSA")
		}
		pkcs1 := x509.MarshalPKCS1PublicKey(&key.rsaKey.PublicKey)
		return pem.EncodeToMemory(
			&pem.Block{Type: pemTypeRSAPublic, Bytes: pkcs1},
		), nil

	case Modulus:
		if key.rsaKey == nil {
			return nil, fmt.Errorf(errNoKey, ErrNoSigningKey, "RSA")
		}
		return key.rsaKey.N.Bytes(), nil

	default:
		return nil, fmt.Errorf(errUnknownKeyForm, ErrUnknownKeyForm,
			form, SPKIPEM, SPKIDER, PKCS1PEM, Modulus)
	}
}

// corruptSignature replaces a token's signature with bytes no key produced. It
// is not a trap: it is what the JWKS-unreachable experiment presents, because
// that trap asks whether a verifier that cannot fetch keys checks the signature
// at all, and the token has to be one a reachable verifier would refuse.
func CorruptSignature(raw string) (string, error) {
	token, err := Parse(raw)
	if err != nil {
		return "", err
	}

	if len(token.Signature) == 0 {
		return "", fmt.Errorf(errNothingToCorrupt, ErrNotAJWS)
	}

	// Flipping a bit of the real signature, rather than substituting random
	// bytes, keeps the length and the algorithm exactly right. The only thing
	// wrong with the token is that the signature does not verify, which is what
	// makes a 2xx mean the verifier never checked it.
	forged := make([]byte, len(token.Signature))
	copy(forged, token.Signature)
	forged[0] ^= 0xff

	return assemble(token.HeaderJSON, token.ClaimsJSON, forged), nil
}

// mintSignedBy produces a correct token under a named key rather than under the
// provider's current signing key.
func (p *Provider) mintSignedBy(key *Key) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.clock()

	header := Header{Alg: string(RS256), Typ: typAccessJWT, Kid: key.ID}
	claims := Claims{
		Issuer:    p.issuer,
		Subject:   DefaultSubject,
		Audience:  Audience{p.audience},
		Expires:   unix(now.Add(p.lifetime)),
		NotBefore: unix(now),
		IssuedAt:  unix(now),
		ID:        rand.Text(),
	}

	return p.serialize(header, claims, key, nil)
}

// reheader and reclaim mint a correctly signed token with one header or claim
// rewritten. They are the seam the range verifier's tests need to reach the
// checks khaos's own published material can never trip, and they sign properly
// so the token is refused by the check under test rather than by the signature.
func (p *Provider) reheader(edit func(*Header)) string {
	return p.remint(edit, nil)
}

func (p *Provider) reclaim(edit func(*Claims)) string {
	return p.remint(nil, edit)
}

func (p *Provider) remint(header func(*Header), claims func(*Claims)) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	now := p.clock()

	head := Header{Alg: string(RS256), Typ: typAccessJWT, Kid: p.signing.ID}
	body := Claims{
		Issuer:    p.issuer,
		Subject:   DefaultSubject,
		Audience:  Audience{p.audience},
		Expires:   unix(now.Add(p.lifetime)),
		NotBefore: unix(now),
		IssuedAt:  unix(now),
		ID:        rand.Text(),
	}

	if header != nil {
		header(&head)
	}
	if claims != nil {
		claims(&body)
	}

	raw, err := p.serialize(head, body, nil, nil)
	if err != nil {
		return ""
	}

	return raw
}
