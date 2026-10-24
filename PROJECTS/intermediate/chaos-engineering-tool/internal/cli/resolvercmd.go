// ©AngelaMos | 2026
// resolvercmd.go

package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/spf13/cobra"
)

const (
	FlagZone    = "zone"
	FlagControl = "control"
	FlagNetwork = "network"

	serveResolverShort = "serve khaos's chaos DNS resolver (run inside khaos's own container)"
	serveResolverLong  = `serve-resolver runs khaos's authoritative chaos DNS resolver.

It is not meant to be run by hand. khaos imports its own binary as a one-layer
container image and starts this subcommand inside it, because an unprivileged
process cannot bind port 53 and Docker's --dns carries an address with no port.

The resolver listens on 53 inside its own network namespace, publishes nothing
to the host, and is armed over a nonce-authorised control surface on the
container's own address.`

	resolverShort       = "manage khaos's chaos DNS resolver on a network"
	resolverUpShort     = "start a chaos resolver on a network and print what to point a target at"
	resolverDownShort   = "remove khaos's chaos resolver from a network"
	resolverStatusShort = "show khaos's chaos resolvers"

	zoneUsage    = "a name this resolver answers authoritatively, as name=address; repeatable"
	controlUsage = "the zone name no fault ever touches, used as the confirmation control"
	networkUsage = "the Docker network to serve, which must be the target's own"

	resolverNamePrefix = "khaos-resolver-"
	nonceBytes         = dnsrv.NonceBytes

	// A one-file image has nothing to initialise, so this covers scheduling.
	readyTimeout  = 15 * time.Second
	readyInterval = 100 * time.Millisecond

	errZoneFormat  = "%w: %q (expected name=address)"
	errNoZone      = "%w: pass --zone name=address at least once"
	errNoNetwork   = "%w: pass --network"
	errResolverUp  = "the chaos resolver on %s never became ready at %s"
	errNoResolvers = "no chaos resolver is running"

	resolverUpFormat = `chaos resolver serving %s

  container   %s
  address     %s
  control     %s

Point the target at it. --dns is fixed at container creation and Docker offers
no way to change it on a running container, so the target has to be recreated:

  docker run --dns %s ...

  # or, in compose:
  services:
    <your-service>:
      dns: ["%s"]

khaos will refuse to report a verdict until it has seen a query arrive from the
target, so a target that was not recreated is reported as an invalid run rather
than as one that passed.
`

	resolverStatusHeader = "NETWORK                    ADDRESS          CONTAINER"
	resolverStatusRow    = "%-26s %-16s %s\n"
	resolverDownFormat   = "removed the chaos resolver on %s\n"
)

var ErrZoneFormat = errors.New("a --zone entry must be name=address")

var ErrNoZone = errors.New("a chaos resolver needs at least one zone entry")

var ErrNoNetwork = errors.New("a chaos resolver needs a network to serve")

// newServeResolverCmd is hidden because it runs inside the container khaos
// builds from its own binary, and on the host it could not bind port 53.
func newServeResolverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    dockerx.ResolverCommand,
		Short:  serveResolverShort,
		Long:   serveResolverLong,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE:   runServeResolver,
	}

	cmd.Flags().StringArray(FlagZone, nil, zoneUsage)
	cmd.Flags().String(FlagControl, "", controlUsage)

	return cmd
}

func runServeResolver(cmd *cobra.Command, _ []string) error {
	entries, err := cmd.Flags().GetStringArray(FlagZone)
	if err != nil {
		return err
	}

	zone, err := parseZone(entries)
	if err != nil {
		return err
	}

	// Not a flag: /proc/<pid>/cmdline is world-readable, and this nonce is the
	// only authorisation for arming and disarming a DNS fault.
	nonce := os.Getenv(dockerx.EnvResolverNonce)

	control, err := cmd.Flags().GetString(FlagControl)
	if err != nil {
		return err
	}

	resolver, err := dnsrv.New(dnsrv.Config{
		Nonce:   nonce,
		Zone:    zone,
		Control: control,
	})
	if err != nil {
		return err
	}

	if err := resolver.Serve(); err != nil {
		return err
	}

	if err := resolver.ServeControl(""); err != nil {
		_ = resolver.Shutdown()
		return err
	}

	// The container is the fault's lifetime, so there is nothing to roll back;
	// this only makes `docker stop` a clean shutdown rather than a kill.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	return resolver.Shutdown()
}

func parseZone(entries []string) (map[string]string, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf(errNoZone, ErrNoZone)
	}

	zone := make(map[string]string, len(entries))

	for _, entry := range entries {
		name, address, found := strings.Cut(entry, "=")
		if !found || name == "" || address == "" {
			return nil, fmt.Errorf(errZoneFormat, ErrZoneFormat, entry)
		}
		zone[name] = address
	}

	return zone, nil
}

func newResolverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resolver",
		Short: resolverShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(
		newResolverUpCmd(),
		newResolverDownCmd(),
		newResolverStatusCmd(),
	)

	return cmd
}

func newResolverUpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: resolverUpShort,
		Args:  cobra.NoArgs,
		RunE:  runResolverUp,
	}

	cmd.Flags().String(FlagNetwork, "", networkUsage)
	cmd.Flags().StringArray(FlagZone, nil, zoneUsage)
	cmd.Flags().String(FlagControl, "", controlUsage)

	return cmd
}

func runResolverUp(cmd *cobra.Command, _ []string) error {
	networkName, err := cmd.Flags().GetString(FlagNetwork)
	if err != nil {
		return err
	}
	if networkName == "" {
		return fmt.Errorf(errNoNetwork, ErrNoNetwork)
	}

	entries, err := cmd.Flags().GetStringArray(FlagZone)
	if err != nil {
		return err
	}

	zone, err := parseZone(entries)
	if err != nil {
		return err
	}

	control, err := cmd.Flags().GetString(FlagControl)
	if err != nil {
		return err
	}
	if control == "" {
		control = dockerx.ResolverControlName(networkName)
		zone[control] = anyZoneAddress(zone)
	}

	ctx := cmd.Context()

	docker, err := dockerx.Open(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = docker.Close() }()

	nonce, err := newNonce()
	if err != nil {
		return err
	}

	resolver, err := docker.RunResolver(ctx, dockerx.ResolverSpec{
		Network: networkName,
		Name:    resolverNamePrefix + networkName,
		Nonce:   nonce,
		Zone:    zone,
		Control: control,
	})
	if err != nil {
		return err
	}

	if err := waitReady(ctx, resolver); err != nil {
		return docker.DiscardResolver(ctx, resolver.ID, err)
	}

	_, err = fmt.Fprintf(
		cmd.OutOrStdout(),
		resolverUpFormat,
		resolver.Network,
		resolver.Name,
		resolver.Address,
		dockerx.ResolverControlURL(resolver.Address),
		resolver.Address,
		resolver.Address,
	)

	return err
}

func waitReady(ctx context.Context, resolver dockerx.Resolver) error {
	client := dnsrv.NewClient(
		resolver.Address,
		dockerx.ResolverControlURL(resolver.Address),
		resolver.Nonce,
		"",
	)

	deadline := time.Now().Add(readyTimeout)

	for time.Now().Before(deadline) {
		if client.Healthy(ctx) {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readyInterval):
		}
	}

	return fmt.Errorf(
		errResolverUp,
		resolver.Network,
		dockerx.ResolverControlURL(resolver.Address),
	)
}

func newResolverDownCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "down",
		Short: resolverDownShort,
		Args:  cobra.NoArgs,
		RunE:  runResolverDown,
	}

	cmd.Flags().String(FlagNetwork, "", networkUsage)

	return cmd
}

func runResolverDown(cmd *cobra.Command, _ []string) error {
	networkName, err := cmd.Flags().GetString(FlagNetwork)
	if err != nil {
		return err
	}
	if networkName == "" {
		return fmt.Errorf(errNoNetwork, ErrNoNetwork)
	}

	ctx := cmd.Context()

	docker, err := dockerx.Open(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = docker.Close() }()

	resolver, err := docker.FindResolver(ctx, networkName)
	if err != nil {
		return err
	}

	if err := docker.RemoveResolver(ctx, resolver.ID); err != nil {
		return err
	}

	_, err = fmt.Fprintf(cmd.OutOrStdout(), resolverDownFormat, networkName)

	return err
}

func newResolverStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: resolverStatusShort,
		Args:  cobra.NoArgs,
		RunE:  runResolverStatus,
	}
}

func runResolverStatus(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	docker, err := dockerx.Open(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = docker.Close() }()

	resolvers, err := docker.Resolvers(ctx)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()

	if len(resolvers) == 0 {
		_, err := fmt.Fprintln(out, errNoResolvers)
		return err
	}

	if _, err := fmt.Fprintln(out, resolverStatusHeader); err != nil {
		return err
	}

	for _, resolver := range resolvers {
		if _, err := fmt.Fprintf(
			out,
			resolverStatusRow,
			resolver.Network,
			resolver.Address,
			resolver.Name,
		); err != nil {
			return err
		}
	}

	return nil
}

func newNonce() (string, error) {
	buffer := make([]byte, nonceBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

// anyZoneAddress points a generated control name at a real zone's address.
func anyZoneAddress(zone map[string]string) string {
	for _, address := range zone {
		return address
	}
	return ""
}
