// ©AngelaMos | 2026
// matrix_test.go

package verifier_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
)

const (
	claimShift = time.Hour
	// The hold has to exceed the verifier's own upstream timeout or the trap is
	// not expressible: a caller whose timeout is longer than the hold sees a
	// slow SUCCESS, which is correct behaviour and not a finding. That is a real
	// property of the experiment, not of this test, and it is why the delay
	// default is generous against the range.
	slowHold = 4 * upstreamTimeout

	// Short, and shorter than slowHold. The range gateway uses 500ms and so does
	// this, so the matrix measures the timeout the fixture actually ships.
	upstreamTimeout = 500 * time.Millisecond
	keyTTL          = 10 * time.Millisecond
	decisionTTL     = 10 * time.Millisecond
	settleFor       = 30 * time.Millisecond
)

// subject is one credential khaos presents, the trap that produced it, and the
// verifier modes that must let it through. Everything not named here must refuse
// it, which is the half of the matrix that actually has teeth: a trap no mode
// accepts is undetectable, and a trap EVERY mode accepts is not testing the bug
// it names.
type subject struct {
	trap idp.Kind

	// arm is the trap to arm on the provider before the credential is presented,
	// for the traps whose fault lives at an endpoint rather than in the token.
	arm func(*idp.Provider) idp.Trap

	// present produces the credential.
	present func(*idp.Provider) (string, error)

	// beforeFault mints the credential BEFORE the trap is armed, for the traps
	// whose whole point is a token that was legitimate when it was issued. It is
	// declared rather than inferred: inferring it from the trap's shape minted
	// every forgery before its own trap was armed, so every cell in the matrix
	// was presenting an honest token and the correct verifier "failed" twelve
	// times over for allowing it.
	beforeFault bool

	// acceptedBy is every mode that must allow it. For the rotation subject this
	// is read the other way round: see mustAllow.
	acceptedBy []verifier.Mode

	// mustAllow inverts the assertion. The rotation subject is a CORRECTLY
	// signed current token, so every mode must accept it and the named ones are
	// the modes that wrongly refuse. That is the one place in this family where
	// refusing is the defect.
	mustAllow bool
}

func forgery(kind idp.Kind, accepted ...verifier.Mode) subject {
	return subject{
		trap:       kind,
		arm:        func(*idp.Provider) idp.Trap { return idp.Trap{Kind: kind} },
		present:    func(p *idp.Provider) (string, error) { return p.TrappedToken() },
		acceptedBy: accepted,
	}
}

func subjects() []subject {
	return []subject{
		forgery(idp.AlgNone, verifier.AlgAny),
		{
			trap: idp.AlgConfusion,
			arm: func(*idp.Provider) idp.Trap {
				return idp.Trap{Kind: idp.AlgConfusion, KeyForm: idp.SPKIPEM}
			},
			present:    func(p *idp.Provider) (string, error) { return p.TrappedToken() },
			acceptedBy: []verifier.Mode{verifier.AlgAny},
		},
		forgery(idp.EmbeddedJWK, verifier.TrustEmbeddedKey),
		{
			trap: idp.ClaimExpired,
			arm: func(*idp.Provider) idp.Trap {
				return idp.Trap{Kind: idp.ClaimExpired, Delay: claimShift}
			},
			present:    func(p *idp.Provider) (string, error) { return p.TrappedToken() },
			acceptedBy: []verifier.Mode{verifier.SkipClaims},
		},
		{
			trap: idp.ClaimNotYetValid,
			arm: func(*idp.Provider) idp.Trap {
				return idp.Trap{Kind: idp.ClaimNotYetValid, Delay: claimShift}
			},
			present:    func(p *idp.Provider) (string, error) { return p.TrappedToken() },
			acceptedBy: []verifier.Mode{verifier.SkipClaims},
		},
		forgery(idp.ClaimWrongAudience, verifier.SkipClaims),
		forgery(idp.ClaimForeignIssuer, verifier.SkipClaims),
		forgery(idp.SignatureTruncated, verifier.WeakSignature),
		forgery(idp.SignatureZero, verifier.WeakSignature),
		forgery(idp.SignatureWeakKey, verifier.AnyKeySize),

		// The highest-value trap in the archive. The credential is minted and
		// corrupted BEFORE the key set goes away, so a verifier with warm keys
		// refuses it and only one that skips verification on a fetch failure
		// lets it through.
		{
			trap: idp.JWKSUnreachable,
			present: func(p *idp.Provider) (string, error) {
				honest, err := p.HonestToken()
				if err != nil {
					return "", err
				}
				return idp.CorruptSignature(honest)
			},
			arm:         func(*idp.Provider) idp.Trap { return idp.Trap{Kind: idp.JWKSUnreachable} },
			acceptedBy:  []verifier.Mode{verifier.JWKSFailOpen},
			beforeFault: true,
		},

		{
			trap:    idp.KidRollover,
			present: func(p *idp.Provider) (string, error) { return p.HonestToken() },
			arm:     func(*idp.Provider) idp.Trap { return idp.Trap{Kind: idp.KidRollover} },
			acceptedBy: []verifier.Mode{
				verifier.JWKSCacheForever,
				verifier.JWKSRefetchOnKidOnly,
			},
			beforeFault: true,
		},

		// The mirror, and the only inverted row. The credential is minted AFTER
		// an overlapping rotation, so it is correctly signed under a currently
		// published key and every verifier must accept it. The one that caches
		// forever never sees the new key and wrongly refuses, which is the
		// availability failure rotation is supposed to avoid.
		{
			trap:       idp.KeyRotation,
			arm:        func(*idp.Provider) idp.Trap { return idp.Trap{Kind: idp.KeyRotation} },
			present:    func(p *idp.Provider) (string, error) { return p.TrappedToken() },
			acceptedBy: []verifier.Mode{verifier.JWKSCacheForever},
			mustAllow:  true,
		},

		opaque(idp.IntrospectionError, nil),
		opaque(idp.IntrospectionMalformed, nil),
		opaque(idp.IntrospectionSlow, func(*idp.Provider) idp.Trap {
			return idp.Trap{Kind: idp.IntrospectionSlow, Delay: slowHold}
		}),
	}
}

// opaque builds a subject for the introspection traps. The credential is a real,
// active grant: the finding is that the verifier allows it without a usable
// answer, and a credential that was never valid could not establish that.
func opaque(kind idp.Kind, arm func(*idp.Provider) idp.Trap) subject {
	if arm == nil {
		arm = func(*idp.Provider) idp.Trap { return idp.Trap{Kind: kind} }
	}

	return subject{
		trap:       kind,
		present:    func(p *idp.Provider) (string, error) { return p.Opaque(), nil },
		arm:        arm,
		acceptedBy: []verifier.Mode{verifier.IntrospectFailOpen},
	}
}

// revoked is handled separately because the credential has to be ALLOWED once,
// so a decision lands in the cache, before it is revoked. Without that first
// allow there is nothing cached and every mode correctly refuses.
func TestRevokedCredentialIsHonouredOnlyByAForeverCache(t *testing.T) {
	for _, mode := range verifier.Modes() {
		t.Run(mode, func(t *testing.T) {
			provider, v := pair(t, verifier.Mode(mode))

			credential := provider.Revocable()

			if decision := v.Decide(credential); !decision.Allow {
				t.Fatalf(
					"the provider's own active credential was refused before anything was revoked: %s",
					decision.Reason,
				)
			}

			if err := provider.Arm(
				idp.Trap{Kind: idp.Revoke, Credential: credential},
			); err != nil {
				t.Fatalf("revoke: %v", err)
			}

			// Past the decision cache's own lifetime, so a correct verifier has
			// to ask again. The forever cache never will.
			time.Sleep(settleFor)

			decision := v.Decide(credential)

			wantAllow := verifier.Mode(mode) == verifier.DecisionCacheForever

			if decision.Allow != wantAllow {
				t.Fatalf(
					"mode %s allowed a revoked credential = %v, want %v (%s)",
					mode,
					decision.Allow,
					wantAllow,
					decision.Reason,
				)
			}
		})
	}
}

// The matrix. Every trap against every mode, with the full expectation on both
// sides: the named modes must accept and every other mode must refuse.
//
// The "must refuse" half is what makes this a census rather than a demo. A trap
// that no mode accepts is undetectable and would ship as an experiment that can
// only ever report HELD, which is the exact failure this project has already
// paid for once: the first `identity.idp_outage` reported `passed / HELD`
// against a range containing the bug it names.
func TestEveryTrapIsCaughtByCorrectAndLetThroughOnlyByItsOwnBug(t *testing.T) {
	all := subjects()

	covered := map[idp.Kind]bool{idp.Revoke: true}
	for _, each := range all {
		covered[each.trap] = true
	}

	for _, kind := range idp.Kinds() {
		if !covered[idp.Kind(kind)] {
			t.Errorf(
				"trap %s has no row in the matrix, so nothing proves it is detectable",
				kind,
			)
		}
	}

	for _, each := range all {
		for _, mode := range verifier.Modes() {
			t.Run(fmt.Sprintf("%s/%s", each.trap, mode), func(t *testing.T) {
				provider, v := pair(t, verifier.Mode(mode))

				credential, armed := stage(t, provider, v, each)

				decision := v.Decide(credential)

				want := each.expects(verifier.Mode(mode))

				if decision.Allow != want {
					t.Fatalf(
						"%s under %s: allowed = %v, want %v (verifier said: %s; provider observed: %s)",
						each.trap,
						mode,
						decision.Allow,
						want,
						decision.Reason,
						armed,
					)
				}
			})
		}
	}
}

// expects is the expectation for one cell. The inverted row reads the accepted
// list as the modes that WRONGLY refuse, because there the correct answer is to
// allow.
func (s subject) expects(mode verifier.Mode) bool {
	named := slices.Contains(s.acceptedBy, mode)

	if s.mustAllow {
		return !named
	}

	return named
}

// stage warms the verifier's caches, presents the credential in the right order
// relative to the fault, and returns what the provider's own oracle saw.
//
// The ordering is the load-bearing part. A token that has to predate the fault
// is minted first; the caches are warmed before the fault so a verifier has
// something stale to serve; and the trap is confirmed through the provider's own
// surface so a cell that fails cannot be blamed on a fault that never landed.
func stage(
	t *testing.T,
	provider *idp.Provider,
	v *verifier.Verifier,
	s subject,
) (string, string) {
	t.Helper()

	// Warm the verifier the way khaos's baseline does, by presenting an honest
	// credential before anything is armed. This is not scaffolding: the two
	// cache traps are ONLY expressible against a warm cache, because a verifier
	// whose first fetch happens after the rotation sees the rotated key set and
	// behaves identically to a correct one. Measured here: without the warm-up
	// the forever-cache rows reported the opposite of the truth in both
	// directions, which is worse than reporting nothing.
	warm, err := provider.HonestToken()
	if err != nil {
		t.Fatalf("mint the warm-up credential: %v", err)
	}

	if decision := v.Decide(warm); !decision.Allow {
		t.Fatalf(
			"the verifier refused an honest credential before any fault was armed (%s), so nothing it does afterwards can be attributed to the trap",
			decision.Reason,
		)
	}

	early := ""
	if s.beforeFault {
		minted, err := s.present(provider)
		if err != nil {
			t.Fatalf("mint before arming %s: %v", s.trap, err)
		}
		early = minted
	}

	trap := s.arm(provider)

	if err := provider.Arm(trap); err != nil {
		t.Fatalf("arm %s: %v", s.trap, err)
	}

	observable, confirmed, err := provider.Observe(context(t), s.trap)
	if err != nil || !confirmed {
		t.Fatalf(
			"khaos could not confirm %s on its own provider (%v), so this cell would be measuring nothing",
			s.trap,
			orErr(err, observable),
		)
	}

	// Past the key cache's lifetime, so a correct verifier refetches and sees
	// the armed state. Without this the rotation and JWKS rows would be answered
	// from keys fetched before the fault and every mode would look the same.
	time.Sleep(settleFor)

	if early != "" {
		return early, observable
	}

	minted, err := s.present(provider)
	if err != nil {
		t.Fatalf("mint under %s: %v", s.trap, err)
	}

	return minted, observable
}
