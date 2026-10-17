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
