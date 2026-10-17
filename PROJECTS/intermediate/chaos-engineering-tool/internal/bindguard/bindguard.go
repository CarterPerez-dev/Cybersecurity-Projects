// ©AngelaMos | 2026
// bindguard.go

package bindguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

const (
	lowestUnprivilegedPort = 1024
	ephemeralPort          = 0

	// Exported because the tiers' own tests derive a bridge and a non-bridge
	// address from sysfs INDEPENDENTLY, rather than asking this package which
	// is which: a test that picked its input with the predicate under test
	// would agree with that predicate's mistake. These two are facts about
	// Linux, not logic, so sharing them costs nothing.
	SysClassNet  = "/sys/class/net"
	BridgeMarker = "bridge"

	errWildcard = "%w: %q binds every address on this host, and %s must not be reachable off it; bind the Docker bridge gateway instead"

	errPrivileged = "%w: %q is a privileged port"

	errBadAddr = "%w: %q is not a host and port (%v)"

	errOffBox = "%w: %q is not on loopback or on a Docker bridge, so it is reachable from outside this host and a container cannot reach it anyway; bind the bridge gateway the daemon reports"

	errUnmanaged = "%w: %q is not a gateway of any network the Docker daemon manages, and %s must not be reachable from anything but the target under test. khaos checked %d network gateway(s). A kernel bridge is not enough: a CNI pod bridge, a swarm gateway bridge and a host interface enslaved to a bridge all look like one, and the last of those is the host's own routable address"
)

// ErrUnsafeBind is one sentinel for every listener khaos opens. Each tier
// wraps it with its own subject, so a refusal names what was about to be
// exposed rather than the rule that stopped it.
var ErrUnsafeBind = errors.New("khaos will not bind there")

// Check refuses an address khaos must not serve a deliberately broken
// dependency on. It is shared rather than restated because every one of these
// listeners is a thing an operator would be horrified to find on their
// network: a fault proxy in front of a dependency under test, and an
// authorization service that allows every credential it was not told to deny.
//
// subject is what the refusal names, in words, from the tier's own vocabulary.
//
// The test is the ROUTING property rather than the address: loopback, or a
// bridge, identified by its sysfs `bridge` directory rather than by its name,
// because a target in a container has to be able to reach it and nothing else
// should.
func Check(listenAddr, subject string) error {
	host, portText, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return fmt.Errorf(errWildcard, ErrUnsafeBind, listenAddr, subject)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	if port != ephemeralPort && port < lowestUnprivilegedPort {
		return fmt.Errorf(errPrivileged, ErrUnsafeBind, listenAddr)
	}

	if ip.IsLoopback() {
		return nil
	}

	onBridge, err := bridgeHosts(ip)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	if !onBridge {
		return fmt.Errorf(errOffBox, ErrUnsafeBind, listenAddr)
	}

	return nil
}

// Managed is the narrow check, and Check is the structural one. Check asks
// "could a container reach this and nothing off the host"; this asks "is this
// an address DOCKER manages", which is the question `/sys/class/net/<if>/bridge`
// cannot answer: that file exists for every kernel bridge device, including a
// CNI pod bridge, a swarm gateway bridge, every user-defined Docker network's
// bridge, and -- on a host whose LAN interface is enslaved to one -- the
// routable LAN address itself. Check accepted all of those while its own
// comment claimed nothing but the target could reach the listener.
//
// gateways comes from the daemon, so this lives wherever a Docker client does
// and the structural check stays in the packages that bind. An empty set is a
// refusal rather than a pass: khaos could not establish the allowed addresses,
// and binding anyway is the behaviour this exists to stop.
func Managed(listenAddr, subject string, gateways []string) error {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf(errBadAddr, ErrUnsafeBind, listenAddr, err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf(errWildcard, ErrUnsafeBind, listenAddr, subject)
	}

	if ip.IsLoopback() {
		return nil
	}

	for _, gateway := range gateways {
		if managed := net.ParseIP(gateway); managed != nil &&
			managed.Equal(ip) {
			return nil
		}
	}

	return fmt.Errorf(
		errUnmanaged,
		ErrUnsafeBind,
		listenAddr,
		subject,
		len(gateways),
	)
}

func bridgeHosts(ip net.IP) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			network, ok := addr.(*net.IPNet)
			if !ok || !network.IP.Equal(ip) {
				continue
			}

			_, err := os.Stat(
				filepath.Join(SysClassNet, iface.Name, BridgeMarker),
			)

			return err == nil, nil
		}
	}

	return false, nil
}
