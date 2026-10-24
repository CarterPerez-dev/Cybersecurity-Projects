// ©AngelaMos | 2026
// refuse.go

package dockerx

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	refusalFormat   = "refused %s: %s"
	unconfinedValue = "unconfined"
	noProject       = "no compose project"
	pathSeparator   = "/"
	rootPath        = "/"
)

type Refusal struct {
	Predicate string
	Target    string
	Reason    string
	Fix       string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf(refusalFormat, r.Target, r.Reason)
}

type Predicate struct {
	Name  string
	Check func(Target, Guard) *Refusal
}

const (
	PredicateNotInspected    = "incomplete-inspection"
	PredicateConsentMissing  = "consent-label-missing"
	PredicateConsentNotTrue  = "consent-label-not-true"
	PredicateIdentityChanged = "identity-changed"
	PredicateSelfTarget      = "self-target"
	PredicateHostNetwork     = "host-network-mode"
	PredicateSharedNamespace = "shared-network-namespace"
	PredicateNamespacePeer   = "namespace-joined-by-peer"
	PredicateHostNamespace   = "host-namespace"
	PredicatePrivileged      = "privileged-container"
	PredicateDangerousCap    = "dangerous-capability"
	PredicateDeviceAccess    = "host-device-access"
	PredicateUnconfined      = "unconfined-security-profile"
	PredicateSocketReachable = "docker-socket-reachable"
	PredicateScopeMismatch   = "outside-declared-scope"
	PredicateNotRunning      = "container-not-running"
)

var predicates = []Predicate{
	{PredicateNotInspected, checkNotInspected},
	{PredicateConsentMissing, checkConsentMissing},
	{PredicateConsentNotTrue, checkConsentNotTrue},
	{PredicateIdentityChanged, checkIdentityChanged},
	{PredicateSelfTarget, checkSelfTarget},
	{PredicateHostNetwork, checkHostNetwork},
	{PredicateSharedNamespace, checkSharedNamespace},
	{PredicateNamespacePeer, checkNamespacePeer},
	{PredicateHostNamespace, checkHostNamespace},
	{PredicatePrivileged, checkPrivileged},
	{PredicateDangerousCap, checkDangerousCapability},
	{PredicateDeviceAccess, checkDeviceAccess},
	{PredicateUnconfined, checkUnconfined},
	{PredicateSocketReachable, checkSocketReachable},
	{PredicateScopeMismatch, checkScopeMismatch},
	{PredicateNotRunning, checkNotRunning},
}

func Refuse(t Target, g Guard) *Refusal {
	for _, p := range predicates {
		if refusal := p.Check(t, g); refusal != nil {
			return refusal
		}
	}
	return nil
}

func refuse(predicate string, t Target, reason, fix string) *Refusal {
	return &Refusal{
		Predicate: predicate,
		Target:    t.Name,
		Reason:    reason,
		Fix:       fix,
	}
}

func checkNotInspected(t Target, _ Guard) *Refusal {
	if t.Inspected {
		return nil
	}
	return refuse(
		PredicateNotInspected,
		t,
		"this target was not built from a full container inspection, so the fields the safety checks read are unset rather than known-safe",
		"resolve the target through khaos rather than constructing it from a cached or partial record",
	)
}

func checkConsentMissing(t Target, _ Guard) *Refusal {
	if _, ok := t.Labels[LabelConsent]; ok {
		return nil
	}
	return refuse(
		PredicateConsentMissing,
		t,
		"the container carries no "+LabelConsent+" label, so its owner never consented to fault injection",
		"add `labels: [\""+LabelConsent+"="+ConsentValue+"\"]` to this service in your compose file and recreate it",
	)
}

func checkConsentNotTrue(t Target, _ Guard) *Refusal {
	value, ok := t.Labels[LabelConsent]
	if !ok || value == ConsentValue {
		return nil
	}
	return refuse(
		PredicateConsentNotTrue,
		t,
		fmt.Sprintf(
			"the %s label reads %q, and consent must be exactly %q",
			LabelConsent,
			value,
			ConsentValue,
		),
		"set "+LabelConsent+"="+ConsentValue+" exactly, or remove the label entirely",
	)
}

func checkIdentityChanged(t Target, g Guard) *Refusal {
	if g.ExpectedID == "" || t.ID == g.ExpectedID {
		return nil
	}
	return refuse(
		PredicateIdentityChanged,
		t,
		"the container was replaced since the plan was made: expected "+ShortID(
			g.ExpectedID,
		)+", found "+t.Short(),
		"re-run the plan so khaos resolves the container that exists now",
	)
}

func checkSelfTarget(t Target, g Guard) *Refusal {
	if g.SelfID == "" || !sameContainer(t.ID, g.SelfID) {
		return nil
	}
	return refuse(
		PredicateSelfTarget,
		t,
		"this is the khaos container itself, and a tool that injects faults into itself cannot roll them back",
		"target a different container",
	)
}

func checkHostNetwork(t Target, _ Guard) *Refusal {
	if !strings.EqualFold(t.NetworkMode, NetworkModeHost) {
		return nil
	}
	return refuse(
		PredicateHostNetwork,
		t,
		"the container runs in host network mode, so its network is the host network and any fault would hit the machine",
		"move the service onto a user-defined bridge network",
	)
}

func checkSharedNamespace(t Target, _ Guard) *Refusal {
	peer, ok := strings.CutPrefix(t.NetworkMode, NetworkModeContainerPfx)
	if !ok {
		return nil
	}
	return refuse(
		PredicateSharedNamespace,
		t,
		"the container shares the network namespace of "+ShortID(
			peer,
		)+"; select that owner so khaos can enumerate every sharing container",
		"target "+ShortID(peer)+" directly once it carries the consent label",
	)
}

func checkNamespacePeer(t Target, _ Guard) *Refusal {
	if len(t.NamespacePeers) == 0 {
		return nil
	}
	return refuse(
		PredicateNamespacePeer,
		t,
		"the network namespace of this container is shared by "+strings.Join(
			t.NamespacePeers,
			", ",
		)+
			", which has not consented, so a fault here would reach it too",
		"stop the sharing container, or give it the consent label so you are injecting into both deliberately",
	)
}

func checkHostNamespace(t Target, _ Guard) *Refusal {
	for _, ns := range []struct{ kind, mode string }{
		{"process", t.PidMode},
		{"IPC", t.IpcMode},
		{"user", t.UsernsMode},
	} {
		if strings.EqualFold(ns.mode, ModeHost) {
			return refuse(
				PredicateHostNamespace,
				t,
				"the container shares the host "+ns.kind+" namespace, so it is not meaningfully isolated from the machine",
				"remove the host "+ns.kind+" namespace setting from this service, or target a different one",
			)
		}
	}
	return nil
}

func checkPrivileged(t Target, _ Guard) *Refusal {
	if !t.Privileged {
		return nil
	}
	return refuse(
		PredicatePrivileged,
		t,
		"the container is privileged, so it is not meaningfully isolated from the host",
		"drop `privileged: true` from this service, or target a different one",
	)
}

func checkDangerousCapability(t Target, _ Guard) *Refusal {
	for _, capability := range t.Capabilities {
		name := strings.TrimPrefix(
			strings.ToUpper(strings.TrimSpace(capability)),
			capPrefix,
		)
		if why, dangerous := dangerousCapabilities[name]; dangerous {
			return refuse(
				PredicateDangerousCap,
				t,
				"the container holds "+capability+", which grants "+why,
				"remove "+capability+" from cap_add, or target a different service",
			)
		}
	}
	return nil
}

func checkDeviceAccess(t Target, _ Guard) *Refusal {
	if len(t.Devices) == 0 {
		return nil
	}
	return refuse(
		PredicateDeviceAccess,
		t,
		"the container is given direct access to host device(s): "+strings.Join(
			t.Devices,
			", ",
		),
		"remove the device passthrough, or target a different service",
	)
}

func checkUnconfined(t Target, _ Guard) *Refusal {
	for _, opt := range t.SecurityOpt {
		if strings.Contains(strings.ToLower(opt), unconfinedValue) {
			return refuse(
				PredicateUnconfined,
				t,
				"the container runs with "+opt+", so its kernel confinement is disabled",
				"remove that security_opt entry, or target a different service",
			)
		}
	}
	return nil
}

func checkSocketReachable(t Target, _ Guard) *Refusal {
	for _, source := range t.BindSources {
		if reason, reachable := socketReachableFrom(source); reachable {
			return refuse(
				PredicateSocketReachable,
				t,
				"the container mounts "+source+", which "+reason+
					", and access to the Docker daemon is equivalent to root on this machine",
				"remove that bind mount, or target a service that cannot reach the daemon",
			)
		}
	}
	return nil
}

func checkScopeMismatch(t Target, g Guard) *Refusal {
	if g.Project == "" || t.Project == g.Project {
		return nil
	}
	found := t.Project
	if found == "" {
		found = noProject
	}
	return refuse(PredicateScopeMismatch, t,
		"the container belongs to "+found+" but khaos was scoped to "+g.Project,
		"re-run with --project "+found+", or pick a target inside "+g.Project)
}

func checkNotRunning(t Target, _ Guard) *Refusal {
	if t.Running {
		return nil
	}
	return refuse(
		PredicateNotRunning,
		t,
		"the container is not running, so there is no steady state to establish and no behavior to measure",
		"start the container, then re-run",
	)
}

func socketPaths() []string {
	paths := []string{DockerSocketPath, runSocketPath}
	if runtimeDir := xdgRuntimeDir(); runtimeDir != "" {
		paths = append(paths, filepath.Join(runtimeDir, socketBaseName))
	}
	return paths
}

func socketReachableFrom(source string) (string, bool) {
	resolved := resolvePath(source)

	// Containment is DIRECTIONAL. A mount that contains the daemon's state
	// directory exposes it; one the daemon handed out from inside it does not.
	// Every named and anonymous volume lives at
	// /var/lib/docker/volumes/<name>/_data, so a symmetric test refuses every
	// container with a volume - which is every database, every cache and every
	// queue - while blaming the operator for a bind mount they never wrote.
	if !managedVolume(resolved) && overlaps(resolved, daemonStatePath) {
		return "exposes the Docker daemon state directory", true
	}

	for _, socket := range socketPaths() {
		if resolved == socket || resolved == resolvePath(socket) {
			return "is the Docker socket", true
		}
		if isAncestor(resolved, socket) ||
			isAncestor(resolved, resolvePath(socket)) {
			return "contains the Docker socket at " + socket, true
		}
	}

	if filepath.Base(resolved) == socketBaseName {
		return "is named like a Docker socket", true
	}

	return "", false
}

// managedVolume reports whether this path is ONE volume's data directory under
// the daemon's volume root. The `_data` component is required, so the volume
// root itself, the volume metadata beside it, and every other subtree of
// /var/lib/docker stay refused: those expose every volume on the host, or
// another container's filesystem, rather than the one volume the daemon handed
// to this container.
//
// A volume created with `--opt device=/var/run` resolves to the device path and
// never reaches this check, so the narrow allowance cannot be used to smuggle
// the socket in.
func managedVolume(resolved string) bool {
	if !isAncestor(daemonVolumePath, resolved) {
		return false
	}

	for _, element := range strings.Split(
		strings.TrimPrefix(resolved, daemonVolumePath+pathSeparator),
		pathSeparator,
	) {
		if element == volumeDataDir {
			return true
		}
	}

	return false
}

func resolvePath(path string) string {
	if path == "" {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(path)
}

func isAncestor(dir, path string) bool {
	if dir == rootPath {
		return true
	}
	return strings.HasPrefix(path, dir+pathSeparator)
}

func overlaps(a, b string) bool {
	return a == b || isAncestor(a, b) || isAncestor(b, a)
}

func sameContainer(id, other string) bool {
	if id == "" || other == "" {
		return false
	}
	if len(id) < len(other) {
		id, other = other, id
	}
	return strings.HasPrefix(id, other)
}
