// ©AngelaMos | 2026
// discovery_test.go

package rangelab

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
)

// The discovery surface decides which of the range's three gateways an
// experiment is pointed at and where khaos binds its two in-process services.
// It was covered only end to end by a Docker gate that takes a quarter of an
// hour, so every wiring mistake cost a full range cycle to find.
//
// These tests need a reader that answers PER CONTAINER. The package's existing
// fake returns one port and one environment for every container, which cannot
// tell the gateways apart at all.

const (
	directID   = "direct-id"
	proxiedID  = "proxied-id"
	verifierID = "verifier-id"
	idpID      = "idp-id"

	directPort   = 41001
	proxiedPort  = 41002
	proxyPort    = 41003
	verifierPort = 41004
	idpPort      = 41005

	bridgeIP = "10.0.0.1"
	idpIP    = "172.20.0.5"

	testIssuer = "http://host.docker.internal:41005"
)

type tieredReader struct {
	targets []dockerx.Target
	ports   map[string]int
	environ map[string]map[string]string
	bridge  string
	address string
}

func (r tieredReader) Targets(
	context.Context,
	dockerx.Filter,
) ([]dockerx.Target, error) {
	return r.targets, nil
}

func (r tieredReader) PublishedPort(
	_ context.Context,
	id string,
	_ int,
) (int, error) {
	port, ok := r.ports[id]
	if !ok {
		return 0, errors.New("no published port for " + id)
	}
	return port, nil
}

func (r tieredReader) ContainerEnv(
	_ context.Context,
	id string,
) (map[string]string, error) {
	return r.environ[id], nil
}

func (r tieredReader) NetworkAddress(
	context.Context,
	string,
	string,
) (string, error) {
	return r.address, nil
}

func (r tieredReader) BridgeGateway(context.Context) (string, error) {
	return r.bridge, nil
}

func container(id, name string) dockerx.Target {
	return dockerx.Target{
		ID:        id,
		Name:      name,
		Project:   ProjectName,
		Running:   true,
		Inspected: true,
	}
}

// fullRange is every container a complete range runs, with the two khaos-side
// addresses carried in the environment of the container that will dial them.
func fullRange() tieredReader {
	return tieredReader{
		targets: []dockerx.Target{
			container(idpID, IDPName),
			container(directID, GatewayName),
			container(proxiedID, ProxiedGatewayName),
			container(verifierID, VerifierGatewayName),
		},
		ports: map[string]int{
			directID:   directPort,
			proxiedID:  proxiedPort,
			verifierID: verifierPort,
		},
		environ: map[string]map[string]string{
			proxiedID: {
				EnvUpstream: "http://host.docker.internal:" + strconv.Itoa(
					proxyPort,
				),
			},
			verifierID: {EnvIssuer: testIssuer},
		},
		bridge:  bridgeIP,
		address: idpIP,
	}
}

func TestDiscoverFindsAllThreeTiers(t *testing.T) {
	lab, err := Discover(context.Background(), fullRange())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	for _, each := range []struct {
		what string
		got  int
		want int
	}{
		{"the direct gateway's port", lab.Port, directPort},
		{"the proxied gateway's port", lab.ProxiedPort, proxiedPort},
		{"the port the proxied gateway dials khaos's proxy on", lab.ProxyPort, proxyPort},
		{"the verifier gateway's port", lab.VerifierPort, verifierPort},
		{"the port the verifier gateway dials khaos's provider on", lab.IdPPort, idpPort},
	} {
		if each.got != each.want {
			t.Errorf("%s = %d, want %d", each.what, each.got, each.want)
		}
	}

	if lab.Issuer != testIssuer {
		t.Errorf("issuer = %q, want %q", lab.Issuer, testIssuer)
	}
}

func TestDiscoveryDoesNotDependOnEarlierOptionalTiers(t *testing.T) {
	for _, missing := range []string{ProxiedGatewayName, VerifierGatewayName} {
		t.Run(missing, func(t *testing.T) {
			reader := fullRange()
			var targets []dockerx.Target
			for _, target := range reader.targets {
				if target.Name != missing {
					targets = append(targets, target)
				}
			}
			targets = append(targets,
				container("secret-id", SecretGatewayName),
				container("control-id", ControlGatewayName))
			reader.targets = targets
			reader.ports["secret-id"] = 42001
			reader.ports["control-id"] = 42002
			reader.environ["control-id"] = map[string]string{
				EnvLimitStore: "redis:6379",
			}
			lab, err := Discover(context.Background(), reader)
			if err != nil {
				t.Fatal(err)
			}
			if lab.SecretPort != 42001 || lab.ControlPort != 42002 ||
				lab.ControlStoreAddr != "redis:6379" {
				t.Fatalf("independent tiers missing: %+v", lab)
			}
			if missing == ProxiedGatewayName &&
				lab.VerifierPort != verifierPort {
				t.Fatal("verifier hidden by missing proxy")
			}
		})
	}
}

// Each tier is probed at its own URL, and they must all differ. Pointing an
// experiment at the wrong one measures a service with no causal connection to
// its fault and reports a clean survival over an armed fault.
func TestTheThreeTiersResolveToThreeDistinctURLs(t *testing.T) {
	lab, err := Discover(context.Background(), fullRange())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	urls := map[string]string{
		"docker-native": lab.ProtectedURL(),
		"proxy":         lab.ProxiedProtectedURL(),
		"identity":      lab.VerifierProtectedURL(),
	}

	seen := map[string]string{}

	for tier, url := range urls {
		if other, clash := seen[url]; clash {
			t.Fatalf("the %s and %s tiers both resolve to %q", tier, other, url)
		}
		seen[url] = tier

		// The range is a deliberately vulnerable stack. Every entry point it
		// publishes must be loopback-only.
		if !strings.HasPrefix(url, "http://127.0.0.1:") {
			t.Errorf("the %s tier is reachable off loopback at %q", tier, url)
		}
	}
}

// A Docker-native or proxy experiment has no use for the verifier gateway, so
// its absence must not fail the whole discovery. Failing over it would break
// every experiment that does not arm khaos's provider.
func TestAMissingVerifierGatewayIsNotFatal(t *testing.T) {
	reader := fullRange()
	reader.targets = reader.targets[:3]

	lab, err := Discover(context.Background(), reader)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if lab.Port != directPort || lab.ProxyPort != proxyPort {
		t.Fatalf(
			"the first two tiers did not survive: port=%d proxy=%d",
			lab.Port,
			lab.ProxyPort,
		)
	}

	if lab.VerifierPort != 0 || lab.IdPPort != 0 || lab.Issuer != "" {
		t.Fatalf(
			"khaos invented an identity tier that is not running: port=%d idp=%d issuer=%q",
			lab.VerifierPort,
			lab.IdPPort,
			lab.Issuer,
		)
	}

	if _, _, err := lab.IdPEndpoint(
		context.Background(),
		reader,
	); !errors.Is(
		err,
		ErrRangeIncomplete,
	) {
		t.Fatalf(
			"IdPEndpoint returned %v, want ErrRangeIncomplete so the refusal names the missing container",
			err,
		)
	}
}

// khaos reads the issuer out of the container rather than remembering what it
// chose, so a container that does not carry one is a named refusal. Guessing
// would mint tokens under an issuer the target refuses, and that refusal reads
// exactly like the target catching the trap.
func TestAVerifierGatewayWithNoUsableIssuerIsRefusedByName(t *testing.T) {
	cases := map[string]map[string]string{
		"no issuer at all":   {},
		"an empty issuer":    {EnvIssuer: ""},
		"an unparseable URL": {EnvIssuer: "ht tp://nope"},
		"a URL with no port": {EnvIssuer: "http://host.docker.internal"},
		"a non-numeric port": {EnvIssuer: "http://host.docker.internal:abc"},
		"a zero port":        {EnvIssuer: "http://host.docker.internal:0"},
	}

	for name, environ := range cases {
		t.Run(name, func(t *testing.T) {
			reader := fullRange()
			reader.environ[verifierID] = environ

			_, err := Discover(context.Background(), reader)

			if !errors.Is(err, ErrRangeIncomplete) {
				t.Fatalf("got %v, want ErrRangeIncomplete", err)
			}

			if !strings.Contains(err.Error(), VerifierGatewayName) {
				t.Fatalf(
					"the refusal does not name the container at fault: %v",
					err,
				)
			}
		})
	}
}

// The same guard on the proxy side, which was also untested.
func TestAProxiedGatewayWithNoUsableUpstreamIsRefusedByName(t *testing.T) {
	cases := map[string]map[string]string{
		"no upstream at all": {},
		"an unparseable URL": {EnvUpstream: "ht tp://nope"},
		"a URL with no port": {EnvUpstream: "http://host.docker.internal"},
	}

	for name, environ := range cases {
		t.Run(name, func(t *testing.T) {
			reader := fullRange()
			reader.environ[proxiedID] = environ

			_, err := Discover(context.Background(), reader)

			if !errors.Is(err, ErrRangeIncomplete) {
				t.Fatalf("got %v, want ErrRangeIncomplete", err)
			}

			if !strings.Contains(err.Error(), ProxiedGatewayName) {
				t.Fatalf(
					"the refusal does not name the container at fault: %v",
					err,
				)
			}
		})
	}
}

// Where khaos binds its identity provider, and under which name it mints.
//
// Both halves are load-bearing and they are never the same string: khaos binds
// the bridge gateway's numeric address because that is the one a container can
// reach, and mints under the name the container was configured to trust. Mixing
// them up got every token refused on the issuer check while the run blamed the
// target.
func TestIdPEndpointBindsTheBridgeAndKeepsTheIssuerVerbatim(t *testing.T) {
	reader := fullRange()

	lab, err := Discover(context.Background(), reader)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	listen, issuer, err := lab.IdPEndpoint(context.Background(), reader)
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		t.Fatalf(
			"the listen address is not a host and port: %q (%v)",
			listen,
			err,
		)
	}

	if host != bridgeIP {
		t.Errorf(
			"khaos would bind %q; it has to bind the discovered bridge gateway %q, because a "+
				"listener anywhere else is unreachable from the container",
			host,
			bridgeIP,
		)
	}

	if port != strconv.Itoa(idpPort) {
		t.Errorf(
			"khaos would bind port %s, and the container will dial %d",
			port,
			idpPort,
		)
	}

	if issuer != testIssuer {
		t.Errorf(
			"khaos would mint under %q and the target trusts %q; one character of difference "+
				"refuses every credential khaos sends",
			issuer,
			testIssuer,
		)
	}

	if host == "127.0.0.1" || host == "0.0.0.0" || host == "" {
		t.Errorf(
			"khaos would bind %q, which is either unreachable from containers or exposed off "+
				"the host; a deliberately-wrong identity provider must be neither",
			host,
		)
	}
}

// A trailing slash on the issuer would make `iss` differ from what the target
// compares against by exactly one character.
func TestTheIssuerIsNormalisedTheSameWayTheTargetNormalisesIt(t *testing.T) {
	reader := fullRange()
	reader.environ[verifierID] = map[string]string{EnvIssuer: testIssuer + "/"}

	lab, err := Discover(context.Background(), reader)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}

	if lab.Issuer != testIssuer {
		t.Fatalf(
			"issuer = %q, want %q with the trailing slash removed, because the verifier "+
				"gateway trims it too and an `iss` that differs by one character is refused",
			lab.Issuer,
			testIssuer,
		)
	}
}

// Every host port khaos binds is a random high one, and all five must differ.
// Two services handed the same port means the second one fails to bind, and the
// range's own compose refuses a missing one rather than defaulting.
func TestFreePortsAreFiveDistinctHighPorts(t *testing.T) {
	for range 20 {
		ports, err := FreePorts()
		if err != nil {
			t.Fatalf("FreePorts: %v", err)
		}

		chosen := map[string]int{
			"gateway":  ports.Gateway,
			"proxied":  ports.Proxied,
			"proxy":    ports.Proxy,
			"verifier": ports.Verifier,
			"idp":      ports.IdP,
		}

		seen := map[int]string{}

		for name, port := range chosen {
			if port < portFloor || port >= portCeil {
				t.Fatalf(
					"%s got port %d, outside the %d-%d range khaos picks from; a conventional "+
						"port is the one most likely already taken",
					name,
					port,
					portFloor,
					portCeil,
				)
			}

			if other, clash := seen[port]; clash {
				t.Fatalf("%s and %s were both given port %d", name, other, port)
			}

			seen[port] = name
		}
	}
}
