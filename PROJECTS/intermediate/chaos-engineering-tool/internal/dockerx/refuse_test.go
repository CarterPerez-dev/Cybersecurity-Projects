// ©AngelaMos | 2026
// refuse_test.go

package dockerx

import (
	"strings"
	"testing"
)

const (
	acceptableID = "9f1c2b3a4d5e6f708192a3b4c5d6e7f88192a3b4c5d6e7f89f1c2b3a4d5e6f70"
	khaosOwnID   = "0011223344556677889900aabbccddee0011223344556677889900aabbccddee"
	peerID       = "ffeeddccbbaa00998877665544332211ffeeddccbbaa009988776655443322ff"
	project      = "shop"
)

func acceptable() (Target, Guard) {
	return Target{
			ID:      acceptableID,
			Name:    "shop-api-1",
			Image:   "shop/api:latest",
			Project: project,
			Service: "api",
			Labels: map[string]string{
				LabelConsent:        ConsentValue,
				LabelComposeProject: project,
			},
			Running:     true,
			NetworkMode: "shop_default",
			BindSources: []string{"/srv/shop/config"},
			Inspected:   true,
		}, Guard{
			Project:    project,
			SelfID:     khaosOwnID,
			ExpectedID: acceptableID,
		}
}

type control struct {
	predicate string
	mutate    func(*Target, *Guard)
}

func controls() []control {
	return []control{
		{
			PredicateNotInspected,
			func(t *Target, _ *Guard) { t.Inspected = false },
		},
		{
			PredicateConsentMissing,
			func(t *Target, _ *Guard) { delete(t.Labels, LabelConsent) },
		},
		{
			PredicateConsentNotTrue,
			func(t *Target, _ *Guard) { t.Labels[LabelConsent] = "yes" },
		},
		{
			PredicateIdentityChanged,
			func(_ *Target, g *Guard) { g.ExpectedID = peerID },
		},
		{PredicateSelfTarget, func(t *Target, g *Guard) { g.SelfID = t.ID }},
		{
			PredicateHostNetwork,
			func(t *Target, _ *Guard) { t.NetworkMode = NetworkModeHost },
		},
		{PredicateSharedNamespace, func(t *Target, _ *Guard) {
			t.NetworkMode = NetworkModeContainerPfx + peerID
		}},
		{PredicateNamespacePeer, func(t *Target, _ *Guard) {
			t.NamespacePeers = []string{"sidecar-1"}
		}},
		{
			PredicateHostNamespace,
			func(t *Target, _ *Guard) { t.PidMode = ModeHost },
		},
		{
			PredicatePrivileged,
			func(t *Target, _ *Guard) { t.Privileged = true },
		},
		{
			PredicateDangerousCap,
			func(t *Target, _ *Guard) { t.Capabilities = []string{"NET_ADMIN"} },
		},
		{
			PredicateDeviceAccess,
			func(t *Target, _ *Guard) { t.Devices = []string{"/dev/sda"} },
		},
		{PredicateUnconfined, func(t *Target, _ *Guard) {
			t.SecurityOpt = []string{"seccomp=unconfined"}
		}},
		{PredicateSocketReachable, func(t *Target, _ *Guard) {
			t.BindSources = append(t.BindSources, DockerSocketPath)
		}},
		{
			PredicateScopeMismatch,
			func(t *Target, _ *Guard) { t.Project = "someone-elses-stack" },
		},
		{PredicateNotRunning, func(t *Target, _ *Guard) { t.Running = false }},
	}
}

func TestAcceptableTargetIsAccepted(t *testing.T) {
	target, guard := acceptable()

	if refusal := Refuse(target, guard); refusal != nil {
		t.Fatalf(
			"the control target was refused by %s (%s), so every refusal test below is vacuous",
			refusal.Predicate,
			refusal.Reason,
		)
	}
}

func TestEachControlFiresExactlyOnePredicate(t *testing.T) {
	for _, c := range controls() {
		t.Run(c.predicate, func(t *testing.T) {
			target, guard := acceptable()
			c.mutate(&target, &guard)

			var fired []string
			for _, p := range predicates {
				if p.Check(target, guard) != nil {
					fired = append(fired, p.Name)
				}
			}

			switch len(fired) {
			case 0:
				t.Fatalf(
					"%s accepted a target that breaks exactly its own invariant",
					c.predicate,
				)
			case 1:
				if fired[0] != c.predicate {
					t.Fatalf(
						"control for %s fired %s instead",
						c.predicate,
						fired[0],
					)
				}
			default:
				t.Fatalf(
					"control for %s fired %d predicates (%s); they alibi each other, so gutting any one stays green",
					c.predicate,
					len(fired),
					strings.Join(fired, ", "),
				)
			}
		})
	}
}

func TestEveryPredicateHasAControl(t *testing.T) {
	covered := make(map[string]bool, len(controls()))
	for _, c := range controls() {
		covered[c.predicate] = true
	}

	for _, p := range predicates {
		if !covered[p.Name] {
			t.Fatalf(
				"predicate %s has no negative control, so nothing proves it ever refuses anything",
				p.Name,
			)
		}
	}

	if len(covered) != len(predicates) {
		t.Fatalf("%d controls for %d predicates", len(covered), len(predicates))
	}
}

func TestEveryRefusalNamesAReasonAndAFix(t *testing.T) {
	for _, c := range controls() {
		t.Run(c.predicate, func(t *testing.T) {
			target, guard := acceptable()
			c.mutate(&target, &guard)

			refusal := Refuse(target, guard)
			if refusal == nil {
				t.Fatalf("%s did not refuse its control", c.predicate)
			}

			if strings.TrimSpace(refusal.Reason) == "" {
				t.Fatalf("%s refused without giving a reason", c.predicate)
			}

			if strings.TrimSpace(refusal.Fix) == "" {
				t.Fatalf(
					"%s refused without telling the operator how to fix it",
					c.predicate,
				)
			}
		})
	}
}

func TestConsentMustBeExactlyTrue(t *testing.T) {
	cases := []struct {
		value     string
		consented bool
	}{
		{"true", true},
		{"TRUE", false},
		{"True", false},
		{"1", false},
		{"yes", false},
		{"false", false},
		{" true", false},
		{"true ", false},
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			target, guard := acceptable()
			target.Labels[LabelConsent] = tc.value

			refused := Refuse(target, guard) != nil
			if refused == tc.consented {
				t.Fatalf(
					"consent value %q: refused=%v, want refused=%v",
					tc.value,
					refused,
					!tc.consented,
				)
			}
		})
	}
}

func TestDangerousCapabilitiesAreRefusedInEverySpelling(t *testing.T) {
	spellings := []string{
		"NET_ADMIN",
		"net_admin",
		"CAP_NET_ADMIN",
		"cap_sys_admin",
		"ALL",
		"SYS_MODULE",
		"CAP_SYS_PTRACE",
		"DAC_READ_SEARCH",
		"SYS_RAWIO",
		"BPF",
		"NET_RAW",
	}

	for _, value := range spellings {
		t.Run(value, func(t *testing.T) {
			target, guard := acceptable()
			target.Capabilities = []string{value}

			refusal := Refuse(target, guard)
			if refusal == nil || refusal.Predicate != PredicateDangerousCap {
				t.Fatalf("capability %q was not refused as dangerous", value)
			}
		})
	}
}

func TestHarmlessCapabilitiesAreAllowed(t *testing.T) {
	target, guard := acceptable()
	target.Capabilities = []string{"CHOWN", "SETUID", "KILL"}

	if refusal := Refuse(target, guard); refusal != nil {
		t.Fatalf("harmless capabilities were refused by %s", refusal.Predicate)
	}
}

func TestSocketIsRefusedThroughEveryReachablePath(t *testing.T) {
	reachable := []string{
		DockerSocketPath,
		"/run/docker.sock",
		"/var/run",
		"/run",
		"/var",
		"/",
		"/var/lib/docker",
		"/var/lib/docker/containers",
		"/home/operator/dsock/docker.sock",
	}

	for _, source := range reachable {
		t.Run(source, func(t *testing.T) {
			target, guard := acceptable()
			target.BindSources = []string{source}

			refusal := Refuse(target, guard)
			if refusal == nil || refusal.Predicate != PredicateSocketReachable {
				t.Fatalf(
					"a bind mount of %q reaches the Docker daemon and was not refused",
					source,
				)
			}
		})
	}
}

// TestDaemonStateContainmentIsDirectional is the control for the one narrow
// allowance inside /var/lib/docker. The symmetric version of this test refused
// every container holding a Docker-managed volume, which is every database,
// cache and queue khaos could ever target, and the refusal told the operator to
// remove a bind mount they never wrote.
//
// Every row in the refused list must stay refused: the allowance is one
// volume's own data directory and nothing else.
func TestDaemonStateContainmentIsDirectional(t *testing.T) {
	refused := []string{
		"/var/lib/docker",
		"/var/lib/docker/",
		"/var/lib/docker/containers",
		"/var/lib/docker/containers/abc123",
		"/var/lib/docker/overlay2",
		"/var/lib/docker/image",
		"/var/lib/docker/volumes",
		"/var/lib/docker/volumes/metadata.db",
		"/var/lib",
		"/var",
		"/",
	}

	for _, source := range refused {
		t.Run("refused"+source, func(t *testing.T) {
			target, guard := acceptable()
			target.BindSources = []string{source}

			refusal := Refuse(target, guard)
			if refusal == nil ||
				refusal.Predicate != PredicateSocketReachable {
				t.Fatalf(
					"a mount of %q reaches daemon state and was not refused",
					source,
				)
			}
		})
	}

	allowed := []string{
		"/var/lib/docker/volumes/pgdata/_data",
		"/var/lib/docker/volumes/pgdata/_data/pg_wal",
		"/var/lib/docker/volumes/019fed45e77b712556a8beb2e4bc7347d/_data",
	}

	for _, source := range allowed {
		t.Run("allowed"+source, func(t *testing.T) {
			target, guard := acceptable()
			target.BindSources = []string{source}

			if refusal := Refuse(target, guard); refusal != nil {
				t.Fatalf(
					"%q is one volume's own data directory, which the daemon hands to the container itself, and it was refused by %s",
					source,
					refusal.Predicate,
				)
			}
		})
	}
}

// TestTheVolumeAllowanceCannotSmuggleTheSocket pins the reason the allowance is
// safe: it is applied to the RESOLVED path, so a volume whose local driver
// points at a sensitive host directory is judged by where it actually lands.
func TestTheVolumeAllowanceCannotSmuggleTheSocket(t *testing.T) {
	smuggled := []string{
		"/var/run",
		"/run",
		DockerSocketPath,
		"/var/lib/docker/volumes/../containers",
		"/var/lib/docker/volumes/../../docker",
	}

	for _, source := range smuggled {
		t.Run(source, func(t *testing.T) {
			target, guard := acceptable()
			target.BindSources = []string{source}

			refusal := Refuse(target, guard)
			if refusal == nil ||
				refusal.Predicate != PredicateSocketReachable {
				t.Fatalf(
					"%q reaches the daemon and was not refused",
					source,
				)
			}
		})
	}
}

func TestOrdinaryBindMountsAreAllowed(t *testing.T) {
	harmless := []string{
		"/srv/app/config",
		"/etc/myapp",
		"/var/log/myapp",
		"/opt/data",
	}

	for _, source := range harmless {
		t.Run(source, func(t *testing.T) {
			target, guard := acceptable()
			target.BindSources = []string{source}

			if refusal := Refuse(target, guard); refusal != nil {
				t.Fatalf(
					"harmless mount %q was refused by %s",
					source,
					refusal.Predicate,
				)
			}
		})
	}
}

func TestHostNamespaceIsRefusedForEveryKind(t *testing.T) {
	kinds := map[string]func(*Target){
		"pid":    func(t *Target) { t.PidMode = ModeHost },
		"ipc":    func(t *Target) { t.IpcMode = ModeHost },
		"userns": func(t *Target) { t.UsernsMode = ModeHost },
	}

	for name, apply := range kinds {
		t.Run(name, func(t *testing.T) {
			target, guard := acceptable()
			apply(&target)

			refusal := Refuse(target, guard)
			if refusal == nil || refusal.Predicate != PredicateHostNamespace {
				t.Fatalf("host %s namespace was not refused", name)
			}
		})
	}
}

func TestSelfTargetMatchesShortAndFullIDs(t *testing.T) {
	target, guard := acceptable()
	guard.SelfID = target.ID[:ShortIDLen]

	refusal := Refuse(target, guard)
	if refusal == nil || refusal.Predicate != PredicateSelfTarget {
		t.Fatal("a short self ID did not match the full container ID")
	}
}

func TestEmptyGuardStillEnforcesTargetProperties(t *testing.T) {
	target, _ := acceptable()
	target.Project = "anything"

	if refusal := Refuse(target, Guard{}); refusal != nil {
		t.Fatalf(
			"an empty guard refused a consenting target via %s",
			refusal.Predicate,
		)
	}

	target.Privileged = true
	if refusal := Refuse(target, Guard{}); refusal == nil {
		t.Fatal("an empty guard stopped enforcing container properties")
	}
}

func TestZeroValueTargetIsRefused(t *testing.T) {
	refusal := Refuse(Target{}, Guard{})
	if refusal == nil {
		t.Fatal(
			"a zero-value Target was accepted; a partially built target must never pass",
		)
	}

	if refusal.Predicate != PredicateNotInspected {
		t.Fatalf(
			"a zero-value Target was refused by %s rather than %s, so the completeness check is not first",
			refusal.Predicate,
			PredicateNotInspected,
		)
	}
}
