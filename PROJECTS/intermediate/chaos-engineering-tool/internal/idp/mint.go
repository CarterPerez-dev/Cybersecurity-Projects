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

// KeyForm is how a verifier loaded the key, and so what bytes the forged MAC
// has to be keyed on.
type KeyForm string

const (
	// SPKIPEM is the default: a `.pem` file read off disk.
	SPKIPEM  KeyForm = "spki-pem"
	SPKIDER  KeyForm = "spki-der"
	PKCS1PEM KeyForm = "pkcs1-pem"

	// Modulus is what a verifier that rebuilt the key from `n` is holding.
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

type grantRequest struct {
	subject  string
	lifetime time.Duration
}

// mintToken produces one credential under the armed trap. Every branch
// corrupts EXACTLY ONE property, and every token carries `typ: at+jwt` so a
// verifier implementing RFC 8725's explicit typing refuses each forgery for
// its OWN defect rather than for its type.
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

	switch trap.Kind {
	case AlgNone, AlgConfusion, EmbeddedJWK:
		return p.mintHeaderTrap(trap, header, claims)

	case ClaimExpired, ClaimNotYetValid, ClaimWrongAudience,
		ClaimForeignIssuer:
		return p.mintClaimTrap(trap, header, claims, now, request.lifetime)

	case SignatureTruncated, SignatureZero, SignatureWeakKey:
		return p.mintSignatureTrap(trap, header, claims)

	default:
		// The endpoint traps act on the provider, so honest is correct here.
		return p.serialize(header, claims, nil, nil)
	}
}

// mintHeaderTrap and its two siblings run under the read lock mintToken
// already holds, so none of them may take it again.
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
		return p.serialize(header, claims, nil, nil)
	}
}

func (p *Provider) mintClaimTrap(
	trap Trap,
	header Header,
	claims Claims,
	now time.Time,
	lifetime time.Duration,
) (string, error) {
	switch trap.Kind {
	case ClaimExpired:
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
		// Signed by a key khaos DOES publish, so only `iss` can refuse it.
		if p.foreign == nil {
			return "", fmt.Errorf(errNoKey, ErrNoSigningKey, "second issuer")
		}
		claims.Issuer = p.foreignIssuer
		header.Kid = p.foreign.ID
		return p.serialize(header, claims, p.foreign, nil)

	default:
		return p.serialize(header, claims, nil, nil)
	}
}

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
		return p.serialize(header, claims, nil, nil)
	}
}

// A nil key means the current signing key; a nil signer signs with the alg the
// HEADER declares, which Key.Sign refuses if the key disagrees.
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

// The HMAC secret for the confusion probe, unreachable under the wrong form.
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

// CorruptSignature is not a trap: the JWKS-unreachable experiment needs it.
func CorruptSignature(raw string) (string, error) {
	token, err := Parse(raw)
	if err != nil {
		return "", err
	}

	if len(token.Signature) == 0 {
		return "", fmt.Errorf(errNothingToCorrupt, ErrNotAJWS)
	}

	// A bit flip keeps the length and algorithm right; only the MAC is wrong.
	forged := make([]byte, len(token.Signature))
	copy(forged, token.Signature)
	forged[0] ^= 0xff

	return assemble(token.HeaderJSON, token.ClaimsJSON, forged), nil
}

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

// One header or claim rewritten, correctly signed, so only it can be refused.
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
