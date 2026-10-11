// ©AngelaMos | 2026
// key_test.go

package idp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

// The worked example from RFC 7638 section 3.1. The specification publishes both
// the JWK and the thumbprint it must produce, which makes this a real
// known-answer test rather than a self-consistency check: khaos's
// canonicalization is implemented from the spec text and this is the spec's own
// answer.
const (
	rfc7638Modulus = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFF" +
		"xuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4" +
		"QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD0" +
		"8qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awa" +
		"pJzKnqDKgw"

	rfc7638Thumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
)

func TestThumbprintMatchesRFC7638WorkedExample(t *testing.T) {
	jwk := JWK{Kty: keyTypeRSA, N: rfc7638Modulus, E: "AQAB"}

	pub, err := jwk.RSAPublicKey()
	if err != nil {
		t.Fatalf("rebuild the RFC's key: %v", err)
	}

	got := thumbprintOf(t, canonicalRSAJWK(pub))

	if got != rfc7638Thumbprint {
		t.Fatalf(
			"RFC 7638 section 3.1 publishes %q, khaos computed %q",
			rfc7638Thumbprint,
			got,
		)
	}
}

// The canonical form is written literally rather than marshalled, so a test has
// to pin the exact bytes: encoding/json would order members by struct
// declaration, and a field reorder would silently change every kid khaos derives
// without changing any key material.
func TestCanonicalRSAJWKIsExactlyTheRequiredMembersInLexicographicOrder(
	t *testing.T,
) {
	jwk := JWK{Kty: keyTypeRSA, N: rfc7638Modulus, E: "AQAB"}

	pub, err := jwk.RSAPublicKey()
	if err != nil {
		t.Fatalf("rebuild the RFC's key: %v", err)
	}

	want := `{"e":"AQAB","kty":"RSA","n":"` + rfc7638Modulus + `"}`

	if got := string(canonicalRSAJWK(pub)); got != want {
		t.Fatalf("canonical form drifted\n got: %s\nwant: %s", got, want)
	}
}

func TestThumbprintIsStableAndKeyDependent(t *testing.T) {
	first, err := NewRSAKey()
	if err != nil {
		t.Fatalf("mint a key: %v", err)
	}

	second, err := NewRSAKey()
	if err != nil {
		t.Fatalf("mint a second key: %v", err)
	}

	again, err := first.Thumbprint()
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}

	if again != first.ID {
		t.Fatalf("the same key produced two kids: %q then %q", first.ID, again)
	}

	if first.ID == second.ID {
		t.Fatal(
			"two different keys produced the same kid, so a rotation would be invisible",
		)
	}
}

func TestECThumbprintUsesTheRequiredMembers(t *testing.T) {
	key, err := NewECKey()
	if err != nil {
		t.Fatalf("mint an EC key: %v", err)
	}

	canonical := string(canonicalECJWK(&key.ecKey.PublicKey))

	// crv, kty, x, y is lexicographic, and the coordinates are fixed-width per
	// RFC 7518 section 6.2.1.2: a short coordinate left unpadded would change the
	// thumbprint for the same key roughly one time in 256.
	for _, member := range []string{`{"crv":"P-256"`, `"kty":"EC"`, `"x":"`, `"y":"`} {
		if !contains(canonical, member) {
			t.Fatalf("canonical EC form is missing %s: %s", member, canonical)
		}
	}

	jwk := key.PublicJWK()
	if decodedLen(t, jwk.X) != p256CoordinateBytes ||
		decodedLen(t, jwk.Y) != p256CoordinateBytes {
		t.Fatalf("coordinates are not fixed-width: x=%d y=%d, want %d each",
			decodedLen(t, jwk.X), decodedLen(t, jwk.Y), p256CoordinateBytes)
	}
}

// This is the differential that makes the weak-key trap trustworthy. khaos
// carries its own PKCS#1 v1.5 implementation because crypto/rsa refuses to sign
// or verify below 1024 bits, so the arithmetic has nowhere to be checked except
// against the standard library at a size the standard library will accept.
func TestRawPKCS1v15AgreesWithTheStandardLibrary(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, strongBits)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	for _, message := range []string{"", "khaos", "a much longer signing input than the first two"} {
		digest := sha256.Sum256([]byte(message))

		library, err := rsa.SignPKCS1v15(
			rand.Reader,
			key,
			crypto.SHA256,
			digest[:],
		)
		if err != nil {
			t.Fatalf("library sign %q: %v", message, err)
		}

		mine, err := signPKCS1v15Raw(key, digest[:])
		if err != nil {
			t.Fatalf("khaos sign %q: %v", message, err)
		}

		if string(library) != string(mine) {
			t.Fatalf(
				"khaos's PKCS#1 v1.5 disagrees with crypto/rsa on %q",
				message,
			)
		}

		if !verifyPKCS1v15Raw(&key.PublicKey, digest[:], library) {
			t.Fatalf(
				"khaos's verify rejected a signature crypto/rsa produced for %q",
				message,
			)
		}
	}
}

// The negative control for that verifier. A verify that always said yes would
// pass the agreement test above, because the agreement test only ever hands it
// correct signatures.
func TestRawPKCS1v15VerifyRejectsWrongSignatures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, strongBits)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	digest := sha256.Sum256([]byte("khaos"))

	signature, err := signPKCS1v15Raw(key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	other := sha256.Sum256([]byte("khaos "))

	cases := map[string][]byte{
		"a flipped bit":      flip(signature, 0),
		"a flipped last bit": flip(signature, len(signature)-1),
		"a truncated value":  signature[:len(signature)-1],
		"an empty value":     {},
		"all zeroes":         make([]byte, len(signature)),
	}

	for name, bad := range cases {
		if verifyPKCS1v15Raw(&key.PublicKey, digest[:], bad) {
			t.Errorf("khaos's verify accepted %s", name)
		}
	}

	if verifyPKCS1v15Raw(&key.PublicKey, other[:], signature) {
		t.Error(
			"khaos's verify accepted a valid signature over a different digest",
		)
	}
}

// The whole premise of the weak-key trap, asserted rather than remembered: the
// standard library will not touch this key, and khaos can.
func TestWeakKeyIsBelowTheLibraryFloorAndStillSigns(t *testing.T) {
	key, err := NewWeakRSAKey()
	if err != nil {
		t.Fatalf("assemble a weak key: %v", err)
	}

	if !key.Weak() {
		t.Fatalf("a %d-bit key did not report as weak", key.rsaKey.N.BitLen())
	}

	if bits := key.rsaKey.N.BitLen(); bits != weakBits {
		t.Fatalf("modulus is %d bits, want exactly %d", bits, weakBits)
	}

	digest := sha256.Sum256([]byte("khaos"))

	if _, err := rsa.SignPKCS1v15(
		rand.Reader,
		key.rsaKey,
		crypto.SHA256,
		digest[:],
	); err == nil {
		t.Fatal(
			"crypto/rsa signed below its own floor; the weak-key trap's premise is gone",
		)
	}

	signature, err := key.Sign(RS256, []byte("khaos"))
	if err != nil {
		t.Fatalf("khaos could not sign with its own weak key: %v", err)
	}

	if err := rsa.VerifyPKCS1v15(
		&key.rsaKey.PublicKey,
		crypto.SHA256,
		digest[:],
		signature,
	); err == nil {
		t.Fatal(
			"crypto/rsa verified below its own floor; the weak-key trap would find nothing",
		)
	}

	if !verifyPKCS1v15Raw(&key.rsaKey.PublicKey, digest[:], signature) {
		t.Fatal(
			"khaos's own weak signature does not verify under khaos's own arithmetic",
		)
	}
}

func TestSignRefusesAnAlgorithmTheKeyCannotCarry(t *testing.T) {
	rsaKey, err := NewRSAKey()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	ecKey, err := NewECKey()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, err := rsaKey.Sign(ES256, []byte("x")); err == nil {
		t.Error("an RSA key signed under ES256")
	}

	if _, err := ecKey.Sign(RS256, []byte("x")); err == nil {
		t.Error("an EC key signed under RS256")
	}

	if _, err := rsaKey.Sign(HS256, []byte("x")); err == nil {
		t.Error("a key signed under HS256, which takes no key of its own")
	}
}

func thumbprintOf(t *testing.T, canonical []byte) string {
	t.Helper()
	sum := sha256.Sum256(canonical)
	return b64(sum[:])
}

func flip(raw []byte, at int) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)
	out[at] ^= 0xff
	return out
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func decodedLen(t *testing.T, encoded string) int {
	t.Helper()
	raw, err := decodeSegment(encoded)
	if err != nil {
		t.Fatalf("decode %q: %v", encoded, err)
	}
	return len(raw)
}
