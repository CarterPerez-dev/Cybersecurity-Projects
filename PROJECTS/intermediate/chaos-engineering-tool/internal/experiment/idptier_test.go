// ©AngelaMos | 2026
// idptier_test.go

package experiment

import (
	"slices"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/probe"
)

const (
	testTargetName = "a-verifier"
	testIssuerURL  = "http://host.docker.internal:45678"
)

func identityInputs() map[string]string {
	return map[string]string{
		ParamTarget: testTargetName,
		ParamURL:    "http://127.0.0.1:1/protected",
		ParamIssuer: testIssuerURL,
	}
}

// identityTier is every catalogued experiment whose fault is a trap on khaos's
// own identity provider.
func identityTier() []Definition {
	out := []Definition{}
	for _, definition := range Catalog() {
		if inject.NeedsIdP(definition.FaultKind) {
			out = append(out, definition)
		}
	}
	return out
}

// The census, both ways. A trap with no experiment is a capability khaos built
// and never exposed; an experiment naming a trap that is not registered cannot
// be injected at all. Either way the catalogue and the provider have drifted.
func TestEveryIdentityTrapHasExactlyOneExperiment(t *testing.T) {
	byTrap := map[string][]string{}

	for _, definition := range identityTier() {
		trap := strings.TrimPrefix(definition.FaultKind, inject.KindIdPPrefix)
		byTrap[trap] = append(byTrap[trap], definition.Name)
	}

	for _, trap := range idp.Kinds() {
		named := byTrap[trap]

		switch len(named) {
		case 0:
			t.Errorf(
				"trap %s has no experiment, so khaos can produce it and no operator can ask for it",
				trap,
			)
		case 1:
		default:
			t.Errorf(
				"trap %s is claimed by %v; one trap is one experiment or `khaos catalog` describes the same fault twice",
				trap,
				named,
			)
		}

		delete(byTrap, trap)
	}

	for trap, named := range byTrap {
		t.Errorf(
			"%v name the trap %s, which khaos's provider does not register",
			named,
			trap,
		)
	}
}

// Every identity experiment has to build from what the range answers and nothing
// else, because every CLI path reaches Build through fillFromRange.
func TestEveryIdentityExperimentBuildsFromTheRangeAnswers(t *testing.T) {
	for _, definition := range identityTier() {
		t.Run(definition.Name, func(t *testing.T) {
			spec, err := Build(definition.Name, identityInputs(), Timing{})
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			if spec.IdP == nil {
				t.Fatal(
					"no provider was built, so the probes have nothing to mint from",
				)
			}

			if spec.IdPTrap == nil {
				t.Fatal(
					"no trap was declared, so the run would stand up a provider and arm nothing",
				)
			}

			// Every trap has to be armable as declared, with ONE stated
			// exception. The revocation's credential is issued by a probe, and no
			// probe has fired when the experiment is built, so that trap is
			// deliberately incomplete until the mutator resolves it at inject
			// time. The exception is asserted in both directions here, so a
			// change that made Revoke carry a build-time credential, or that made
			// any other trap incomplete, fails this test rather than passing it.
			err = spec.IdPTrap.Validate()

			if spec.IdPTrap.Kind == idp.Revoke {
				if err == nil {
					t.Fatal(
						"the revocation trap validated at build time, so it is carrying a credential " +
							"from before the probe that issues one has fired",
					)
				}

				resolved := *spec.IdPTrap
				resolved.Credential = spec.IdP.Revocable()

				if err := resolved.Validate(); err != nil {
					t.Fatalf(
						"the revocation trap is not armable even once a credential is resolved: %v",
						err,
					)
				}

				return
			}

			if err != nil {
				t.Fatalf("the declared trap is not armable: %v", err)
			}

			if spec.Fault.Kind != inject.IdPKind(spec.IdPTrap.Kind) {
				t.Fatalf(
					"the catalogued fault is %q and the trap is %q; the mutator would refuse its own experiment",
					spec.Fault.Kind,
					spec.IdPTrap.Kind,
				)
			}

			if spec.Fault.Target != testTargetName {
				t.Fatalf(
					"the fault names %q, want the target %q",
					spec.Fault.Target,
					testTargetName,
				)
			}
		})
	}
}

// The issuer has to reach the provider. khaos binds the bridge gateway's numeric
// address while the target addresses `host.docker.internal`, so a provider left
// to name itself would mint tokens the target refuses on `iss` for a reason that
// has nothing to do with the trap, and a refusal for the wrong reason reads
// exactly like a target that caught it.
func TestEveryIdentityExperimentMintsUnderTheIssuerItWasGiven(t *testing.T) {
	for _, definition := range identityTier() {
		t.Run(definition.Name, func(t *testing.T) {
			spec, err := Build(definition.Name, identityInputs(), Timing{})
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			if got := spec.IdP.Issuer(); got != testIssuerURL {
				t.Fatalf(
					"the provider issues as %q, want %q",
					got,
					testIssuerURL,
				)
			}

			raw, err := spec.IdP.HonestToken()
			if err != nil {
				t.Fatalf("mint: %v", err)
			}

			token, err := idp.Parse(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			if token.Claims.Issuer != testIssuerURL {
				t.Fatalf(
					"the minted token says iss %q, want %q",
					token.Claims.Issuer,
					testIssuerURL,
				)
			}
		})
	}
}

// The stream wiring is the experiment's whole design and it is not
// interchangeable. These are the expectations, stated once, so a change to any
// one experiment's wiring has to be a change here too.
func TestEachIdentityExperimentWiresTheStreamsItsFindingNeeds(t *testing.T) {
	type expectation struct {
		forged   probe.Expectation
		revoked  bool
		idleness bool
	}

	want := map[string]expectation{
		NameAlgNone:            {forged: probe.ExpectAccepted},
		NameAlgConfusion:       {forged: probe.ExpectAccepted},
		NameEmbeddedJWK:        {forged: probe.ExpectAccepted},
		NameClaimExpired:       {forged: probe.ExpectAccepted},
		NameClaimNotYetValid:   {forged: probe.ExpectAccepted},
		NameClaimWrongAudience: {forged: probe.ExpectAccepted},
		NameClaimForeignIssuer: {forged: probe.ExpectAccepted},
		NameSignatureTruncated: {forged: probe.ExpectAccepted},
		NameSignatureZero:      {forged: probe.ExpectAccepted},
		NameSignatureWeakKey:   {forged: probe.ExpectAccepted},

		// The one forged stream that must be REJECTED during the baseline. Its
		// credential is malformed from the moment it is minted, so a target that
		// never refused it was not checking signatures and its acceptance during
		// the fault proves nothing changed.
		NameJWKSUnreachable: {forged: probe.ExpectRejected},

		// Revoked, not forged: the credential was legitimate when issued and the
		// fault is what took it away. Both bring the idleness discriminator,
		// because both leave a cache that either re-arms or never expires.
		NameKidRollover:  {revoked: true, idleness: true},
		NameRevokedToken: {revoked: true, idleness: true},

		// Neither. The valid stream carries the new key's token and a target that
		// refuses it registers as DENIED, which is the whole experiment.
		NameKeyRotation: {},

		// Neither. The generic invalid control already carries a credential no
		// provider would call active, so a target that accepts it while
		// introspection is useless has invented a value RFC 7662 never gave it.
		NameIntrospectionError:     {},
		NameIntrospectionMalformed: {},
		NameIntrospectionSlow:      {},
	}

	tier := identityTier()

	if len(want) != len(tier) {
		t.Fatalf(
			"this test states expectations for %d experiments and the identity tier has %d",
			len(want),
			len(tier),
		)
	}

	for _, definition := range tier {
		t.Run(definition.Name, func(t *testing.T) {
			expected, stated := want[definition.Name]
			if !stated {
				t.Fatalf(
					"%s has no stated wiring, so nothing pins its design",
					definition.Name,
				)
			}

			spec, err := Build(definition.Name, identityInputs(), Timing{})
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			if (spec.Probes.Forged != nil) != (expected.forged != "") {
				t.Errorf(
					"forged stream present = %v, want %v",
					spec.Probes.Forged != nil,
					expected.forged != "",
				)
			}

			if spec.Probes.ForgedBaseline != expected.forged {
				t.Errorf(
					"forged baseline expectation = %q, want %q",
					spec.Probes.ForgedBaseline,
					expected.forged,
				)
			}

			if (spec.Probes.Revoked != nil) != expected.revoked {
				t.Errorf(
					"revoked stream present = %v, want %v",
					spec.Probes.Revoked != nil,
					expected.revoked,
				)
			}

			if (spec.IdleFor > 0) != expected.idleness {
				t.Errorf(
					"idleness discriminator = %v, want %v",
					spec.IdleFor > 0,
					expected.idleness,
				)
			}

			// Every stream that can carry a finding has to name what khaos did to
			// it, or the verdict falls back to a phrase that describes every
			// experiment identically.
			if spec.Probes.Forged != nil || spec.Probes.Revoked != nil {
				if spec.Defect == "" {
					t.Error(
						"this experiment can produce a finding and does not say what khaos did to the credential",
					)
				}
			}
		})
	}
}

// A forged stream whose credential is captured once would carry the baseline's
// HONEST token into the fault window, so the trap would never be presented and
// every forgery experiment would report a clean survival.
func TestTheForgeryStreamsMintPerSampleAndTheFixedOnesDoNot(t *testing.T) {
	mintsPerSample := map[string]bool{
		NameJWKSUnreachable: false,
	}

	for _, definition := range identityTier() {
		spec, err := Build(definition.Name, identityInputs(), Timing{})
		if err != nil {
			t.Fatalf("build %s: %v", definition.Name, err)
		}

		if spec.Probes.Forged == nil {
			continue
		}

		want, stated := mintsPerSample[definition.Name]
		if !stated {
			want = true
		}

		// Describe is the only thing a probe exposes about how it gets its
		// credential, and it says so explicitly for exactly this reason.
		perSample := strings.Contains(
			spec.Probes.Forged.Describe(),
			"minted per request",
		)

		if perSample != want {
			t.Errorf("%s mints per sample = %v, want %v (%s)",
				definition.Name, perSample, want, spec.Probes.Forged.Describe())
		}
	}
}

// The valid stream proves the target is serving WITHOUT disturbing what the
// experiment measures, and that means a different credential per family.
//
//   - A JWT minted per sample, for the forgery and JWKS experiments. Fresh every
//     time, so a target that stopped trusting khaos's provider is distinguishable
//     from one that never picked up a rotation.
//   - A JWT under a key that is never rotated, for `kid_rollover`. A control
//     under the CURRENT signing key becomes new-key traffic after the rotation,
//     and that traffic is what evicts the retired key — khaos causing the
//     recovery it reports.
//   - A fixed OPAQUE credential, for the four introspection experiments. Those
//     fault the introspection endpoint, so the control has to travel it; a JWT
//     control is validated locally and never reaches the fault at all.
//
// Asserted in every direction, because each choice is a trade and getting any of
// them backwards reintroduces a blind spot this family has already had.
func TestEachFamilysValidControlTravelsThePathItNeedsTo(t *testing.T) {
	opaqueControl := map[string]bool{
		NameIntrospectionError:     true,
		NameIntrospectionMalformed: true,
		NameIntrospectionSlow:      true,
		NameRevokedToken:           true,
	}

	seenOpaque, seenMinted := false, false

	for _, definition := range identityTier() {
		spec, err := Build(definition.Name, identityInputs(), Timing{})
		if err != nil {
			t.Fatalf("build %s: %v", definition.Name, err)
		}

		describe := spec.Probes.Valid.Describe()
		perSample := strings.Contains(describe, "minted per request")

		if opaqueControl[definition.Name] {
			if perSample {
				t.Errorf(
					"%s faults the introspection endpoint and its valid control is minted "+
						"per sample; a JWT control is validated locally and never reaches the fault: %s",
					definition.Name,
					describe,
				)
			}
			seenOpaque = true
			continue
		}

		if !perSample {
			t.Errorf(
				"%s freezes its valid credential: %s",
				definition.Name,
				describe,
			)
		}
		seenMinted = true
	}

	if !seenOpaque || !seenMinted {
		t.Fatal(
			"every experiment landed in one bucket, so this test cannot tell the two apart",
		)
	}
}

// `kid_rollover`'s control is a JWT, so it works against a JWT-only verifier,
// and it is signed by a key that is never rotated, so resolving it never forces
// the refetch that evicts the retired key.
//
// An opaque control also avoids the observer effect and was the first fix, but
// it demands the target support introspection — trading one blind spot for
// another.
func TestTheRolloverControlIsAJWTUnderAKeyThatIsNeverRotated(t *testing.T) {
	spec, err := Build(NameKidRollover, identityInputs(), Timing{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	raw, err := spec.IdP.StableToken()
	if err != nil {
		t.Fatalf("mint the control: %v", err)
	}

	control, err := idp.Parse(raw)
	if err != nil {
		t.Fatalf(
			"the control is not a JWT, so a JWT-only verifier cannot baseline: %v",
			err,
		)
	}

	if control.Header.Kid == spec.IdP.SigningKid() {
		t.Fatal(
			"the control is signed by the CURRENT signing key, so after the rotation it becomes " +
				"the new-key traffic that evicts the retired key",
		)
	}

	if !spec.IdP.PublishedSet().Has(control.Header.Kid) {
		t.Fatal(
			"the control's key is not published, so it cannot be resolved without a refetch",
		)
	}

	// And it survives the rotation still published and still not the signing key,
	// which is what stops it triggering a refetch mid-experiment.
	if err := spec.IdP.Arm(idp.Trap{Kind: idp.KidRollover}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	if !spec.IdP.PublishedSet().Has(control.Header.Kid) {
		t.Fatal("the rotation withdrew the control's key")
	}

	if control.Header.Kid == spec.IdP.SigningKid() {
		t.Fatal("the rotation made the control's key the signing key")
	}
}

// TWO experiments treat refusing as a defect, and the set is pinned because it
// is the only thing in the whole catalogue that makes the directional axis
// anything but decoration: if both ever stopped, nothing would exercise that
// branch. Each one is here for the same reason -- the fault was scoped to one
// credential, so refusing the OTHER one is an outage the fault never called
// for. The rotation publishes both keys precisely so nothing breaks, and the
// authorization dependency denies exactly one credential and keeps allowing
// every other. A third entry has to earn that argument.
func TestRefusingIsTheDefectOnlyWhereTheFaultWasScopedToOneCredential(
	t *testing.T,
) {
	inverted := []string{}

	for _, definition := range Catalog() {
		if definition.Polarity.IsDefect(Denied) {
			inverted = append(inverted, definition.Name)
		}
	}

	want := []string{NameAPIKeyRevoked, NameKeyRotation}
	slices.Sort(want)

	if !slices.Equal(inverted, want) {
		t.Fatalf(
			"the experiments treating DENIED as a defect are %v, want exactly %v",
			inverted,
			want,
		)
	}
}

// And PERMITTED is a defect for EVERY experiment khaos currently ships. The
// rotation experiment declared only DENIED, so a target that started accepting
// credentials it had been refusing drew "this experiment declares PERMITTED to
// be acceptable for this control" and exit 0 — a CI pass over a target that
// failed wide open.
//
// This is asserted over the whole catalogue rather than for that one experiment,
// because the next inverted-polarity experiment will hit the same trap.
func TestEveryExperimentTreatsPermittedAsADefect(t *testing.T) {
	for _, definition := range Catalog() {
		if !definition.Polarity.IsDefect(Permitted) {
			t.Errorf(
				"%s does not treat PERMITTED as a defect, so a target that failed open "+
					"would be reported as acceptable and exit 0",
				definition.Name,
			)
		}

		if len(definition.Polarity.Defects) == 0 {
			t.Errorf("%s declares no defect direction at all", definition.Name)
		}

		if definition.Polarity.Rationale == "" {
			t.Errorf(
				"%s declares a polarity with no rationale",
				definition.Name,
			)
		}
	}
}

// An unknown key form has to be refused at build time with the flag named,
// rather than reaching the provider and producing a MAC over nothing.
func TestAnUnknownKeyFormIsRefusedByName(t *testing.T) {
	inputs := identityInputs()
	inputs[ParamKeyForm] = "pem-ish"

	_, err := Build(NameAlgConfusion, inputs, Timing{})
	if err == nil {
		t.Fatal("an unknown key form was accepted")
	}

	if !strings.Contains(err.Error(), "pem-ish") {
		t.Fatalf("the refusal does not name what was typed: %v", err)
	}
}

// Every key form the provider advertises has to be buildable, or `--help` lists
// a value that does not work.
func TestEveryAdvertisedKeyFormBuilds(t *testing.T) {
	for _, form := range idp.KeyForms() {
		inputs := identityInputs()
		inputs[ParamKeyForm] = form

		if _, err := Build(NameAlgConfusion, inputs, Timing{}); err != nil {
			t.Errorf(
				"key form %q is advertised and does not build: %v",
				form,
				err,
			)
		}
	}
}

// The liveness guard for a fault applied to an ENDPOINT. Declared per
// experiment, asserted in both directions, so neither dropping it from one of
// the four nor adding it to an experiment that faults a credential passes.
func TestOnlyTheEndpointFaultsDeclareAConsultedGuard(t *testing.T) {
	want := map[string]string{
		NameJWKSUnreachable:        ConsultsJWKS,
		NameIntrospectionError:     ConsultsIntrospection,
		NameIntrospectionMalformed: ConsultsIntrospection,
		NameIntrospectionSlow:      ConsultsIntrospection,
	}

	for _, definition := range identityTier() {
		spec, err := Build(definition.Name, identityInputs(), Timing{})
		if err != nil {
			t.Fatalf("build %s: %v", definition.Name, err)
		}

		expected := want[definition.Name]

		if spec.ConsultedWhat != expected {
			t.Errorf(
				"%s declares the guard %q, want %q",
				definition.Name,
				spec.ConsultedWhat,
				expected,
			)
		}

		if (spec.Consulted != nil) != (expected != "") {
			t.Errorf(
				"%s has a counter = %v and a declared endpoint = %v; a declared endpoint with "+
					"no counter is a guard that can never fire",
				definition.Name,
				spec.Consulted != nil,
				expected != "",
			)
		}
	}
}

// And the guard has to actually void the run. A target that validates
// credentials locally never calls introspection, so its baseline looks healthy
// and its fault window looks identical — `passed / HELD`, conclusive, over a
// fault that never reached it.
func TestATargetThatNeverUsedTheFaultedEndpointVoidsTheRun(t *testing.T) {
	healthy := window(
		probe.Accepted,
		probe.Rejected,
		"",
		"",
		MinimumToClaimClosed,
	)

	observation := Observation{
		Baseline:       healthy,
		Fault:          healthy,
		Recovery:       healthy,
		FaultConfirmed: true,
		ConfirmMethod:  "khaos read a 503 off its own introspection endpoint",
		ConsultedWhat:  ConsultsIntrospection,
		Consulted:      0,
	}

	verdict := Judge(observation, idpPolarity)

	if verdict.Epistemic != BaselineNotMet {
		t.Fatalf(
			"epistemic = %s, want %s (%s)",
			verdict.Epistemic,
			BaselineNotMet,
			strings.Join(verdict.Reasons, "; "),
		)
	}

	if !strings.Contains(
		strings.Join(verdict.Reasons, "; "),
		ConsultsIntrospection,
	) {
		t.Fatalf(
			"the refusal does not name the endpoint: %s",
			strings.Join(verdict.Reasons, "; "),
		)
	}

	// The control: the same run where the target DID use the endpoint is judged
	// normally. Without this, a guard that always fired would pass the assertion
	// above.
	observation.Consulted = 1

	if verdict := Judge(observation, idpPolarity); verdict.Epistemic != Passed {
		t.Fatalf("a target that used the endpoint was judged %s, want %s (%s)",
			verdict.Epistemic, Passed, strings.Join(verdict.Reasons, "; "))
	}
}

// An experiment that declares no endpoint must be unaffected, or adding the
// guard would have voided the fourteen experiments that fault a credential.
func TestAnExperimentWithNoDeclaredEndpointIsNotGuarded(t *testing.T) {
	healthy := window(
		probe.Accepted,
		probe.Rejected,
		"",
		"",
		MinimumToClaimClosed,
	)

	observation := Observation{
		Baseline:       healthy,
		Fault:          healthy,
		Recovery:       healthy,
		FaultConfirmed: true,
		Consulted:      0,
	}

	if verdict := Judge(observation, idpPolarity); verdict.Epistemic != Passed {
		t.Fatalf("epistemic = %s, want %s", verdict.Epistemic, Passed)
	}
}

// The two experiments whose absence of a finding covers less than it reads.
// Asserted in both directions: the other sixteen must carry no caveat, or a
// caveat on everything would say nothing.
func TestOnlyTheExperimentsThatMeasureLessCarryAHeldCaveat(t *testing.T) {
	caveated := map[string]string{
		NameAlgConfusion:      "serialization",
		NameIntrospectionSlow: "timeout is longer",
	}

	for _, definition := range identityTier() {
		spec, err := Build(definition.Name, identityInputs(), Timing{})
		if err != nil {
			t.Fatalf("build %s: %v", definition.Name, err)
		}

		fragment, expected := caveated[definition.Name]

		if (spec.HeldCaveat != "") != expected {
			t.Errorf(
				"%s carries a HELD caveat = %v, want %v (%q)",
				definition.Name,
				spec.HeldCaveat != "",
				expected,
				spec.HeldCaveat,
			)
			continue
		}

		if expected && !strings.Contains(spec.HeldCaveat, fragment) {
			t.Errorf(
				"%s's caveat does not mention %q: %s",
				definition.Name,
				fragment,
				spec.HeldCaveat,
			)
		}
	}
}

// And the caveat has to reach the verdict, which only happens on HELD.
func TestTheHeldCaveatIsStatedOnlyWhenTheTargetHeld(t *testing.T) {
	const caveat = "this run tried one of four serializations"

	held := Observation{
		Baseline: window(
			probe.Accepted,
			probe.Rejected,
			"",
			"",
			MinimumToClaimClosed,
		),
		Fault: window(
			probe.Accepted,
			probe.Rejected,
			"",
			"",
			MinimumToClaimClosed,
		),
		Recovery: window(
			probe.Accepted,
			probe.Rejected,
			"",
			"",
			MinimumToClaimClosed,
		),
		FaultConfirmed: true,
		HeldCaveat:     caveat,
	}

	verdict := Judge(held, idpPolarity)

	if verdict.Direction != Held {
		t.Fatalf("direction = %s, want %s", verdict.Direction, Held)
	}

	if !strings.Contains(strings.Join(verdict.Reasons, "; "), caveat) {
		t.Fatalf(
			"a HELD verdict did not state its caveat, so khaos claims it ruled out more than "+
				"it tried: %s",
			strings.Join(verdict.Reasons, "; "),
		)
	}

	// A run that found something does not need the caveat: it found the thing
	// the caveat warns might have been missed.
	leaked := held
	leaked.Fault = window(probe.Accepted, probe.Accepted, "", "", MinimumPaired)

	if found := Judge(
		leaked,
		idpPolarity,
	); strings.Contains(
		strings.Join(found.Reasons, "; "),
		caveat,
	) {
		t.Fatalf(
			"a run that found a bypass still warned that it might have missed one: %s",
			strings.Join(found.Reasons, "; "),
		)
	}
}
