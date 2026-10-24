// ©AngelaMos | 2026
// rangecmd.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/rangelab"
	"github.com/CarterPerez-dev/khaos/internal/render"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/tlsclient"
	"github.com/CarterPerez-dev/khaos/internal/verifier"
	"github.com/CarterPerez-dev/khaos/internal/workspace"
	"github.com/spf13/cobra"
)

var ErrUnknownSecretMode = errors.New(
	"that is not a secret handling the range fixture understands",
)

var ErrUnknownPoolMode = errors.New(
	"that is not a pool configuration the range fixture understands",
)

var ErrUnknownDNSMode = errors.New(
	"that is not a resolution behaviour the range gateway understands",
)

var ErrUnknownAuthzMode = errors.New(
	"that is not an authorization-error handling the range fixture understands",
)

var ErrUnknownFailMode = errors.New("the range has no such fail mode")

const (
	flagFailMode   = "fail-mode"
	flagCacheTTL   = "cache-ttl"
	flagTLSMode    = "tls-mode"
	flagPort       = "port"
	flagQuiet      = "quiet"
	flagWithDB     = "with-db"
	flagPoolMode   = "pool-mode"
	flagSecretMode = "secret-mode"
	flagAuthzMode  = "authz-mode"
	flagDNSMode    = "dns-mode"

	mintedSecrets = 5

	rangeShort = "bring up a target stack that is deliberately breakable"
	rangeLong  = `The range provides disposable gateways and dependencies for network,
identity, TLS, DNS, credential, and security-control experiments.

Choose closed or deliberately defective behavior with the mode flags.
The database tier is optional. Every target carries the consent label,
and published services bind to loopback on available high ports.

Range build files are bundled into khaos, so no source checkout is required.`

	upShort     = "build and start the range, then wait until it answers"
	downShort   = "stop the range and remove everything it created"
	statusShort = "show whether the range is running and where to reach it"

	failModeUsage   = "gateway behavior: closed, open, stale-rearm, or a verifier defect; use ? to list modes"
	cacheTTLUsage   = "how long the gateway caches an authorization decision"
	tlsModeUsage    = "TLS verification behavior: closed or one named verification defect; use ? to list modes"
	portUsage       = "host port for the gateway; the default is a random high port chosen at startup"
	quietUsage      = "suppress compose build and start output"
	secretModeUsage = "secret validation: validated checks every read; unchecked accepts empty values"

	dnsModeUsage = "DNS behavior: reresolve opens a connection per request; pinned reuses one connection"

	authzModeUsage = "authorization behavior: distinguishes, collapses, retries, or cached"

	poolModeUsage = "connection lifetime: unbounded, bounded, or held outside the pool"

	withDBUsage = "also start PostgreSQL, MySQL, MariaDB, and the Redis rate-limit datastore"

	msgStarting          = "building and starting the range"
	msgPortRetry         = "host port %d was taken between the check and the bind; picking another"
	errPortBound         = "could not start the range on host port %d: %w"
	portAttempts         = 3
	msgRangeUp           = "range is up"
	msgRangeDown         = "range is down"
	msgRangeStopped      = "the range is not running; start it with `khaos range up`"
	msgFailMode          = "fail mode %s"
	msgTokenHint         = "a credential is issued on demand, so `khaos run` against the range needs no flags"
	errUnknownPoolMode   = "%w: %q (known pool modes: %s)"
	errUnknownSecretMode = "%w: %q (known secret modes: %s)"
	errUnknownAuthzMode  = "%w: %q (known authorization modes: %s)"
	errUnknownDNSMode    = "%w: %q (known DNS modes: %s)"

	msgStatefulUp      = "the stateful tier is up: PostgreSQL, MySQL, MariaDB and Redis, none of them published to a host port"
	msgPortHint        = "host port %d was chosen at random; pass --port to pin it"
	errUnknownFailMode = "%w: %q (known modes: %s)"

	msgTierDirect   = "docker-native tier  %s"
	msgTierProxied  = "proxy tier          %s, with khaos's fault proxy expected on host port %d"
	msgTierVerifier = "identity tier       %s, trusting khaos's provider as %s"
	msgTierTLS      = "certificate tier    %s, dialling khaos's authority at %s as the %s client"
	msgTierDNS      = "dns tier            %s, resolving %s through khaos's chaos resolver at %s"
	msgTierAuthz    = "authorization tier  %s, asking khaos for a decision at %s"
)

func newRangeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "range",
		Short: rangeShort,
		Long:  rangeLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newRangeUpCmd(), newRangeDownCmd(), newRangeStatusCmd())

	return cmd
}

func newRangeUpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: upShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			failMode, err := cmd.Flags().GetString(flagFailMode)
			if err != nil {
				return err
			}
			cacheTTL, err := cmd.Flags().GetString(flagCacheTTL)
			if err != nil {
				return err
			}
			tlsMode, err := cmd.Flags().GetString(flagTLSMode)
			if err != nil {
				return err
			}
			port, err := cmd.Flags().GetInt(flagPort)
			if err != nil {
				return err
			}
			quiet, err := cmd.Flags().GetBool(flagQuiet)
			if err != nil {
				return err
			}
			withDB, err := cmd.Flags().GetBool(flagWithDB)
			if err != nil {
				return err
			}
			poolMode, err := cmd.Flags().GetString(flagPoolMode)
			if err != nil {
				return err
			}
			secretMode, err := cmd.Flags().GetString(flagSecretMode)
			if err != nil {
				return err
			}
			authzMode, err := cmd.Flags().GetString(flagAuthzMode)
			if err != nil {
				return err
			}
			dnsMode, err := cmd.Flags().GetString(flagDNSMode)
			if err != nil {
				return err
			}
			return runRangeUp(
				cmd.Context(),
				cmd.OutOrStdout(),
				failMode,
				cacheTTL,
				tlsMode,
				port,
				quiet,
				withDB,
				rangeModes{
					pool:   poolMode,
					secret: secretMode,
					authz:  authzMode,
					dns:    dnsMode,
				},
			)
		},
	}

	cmd.Flags().String(flagFailMode, rangelab.FailModeShut, failModeUsage)
	cmd.Flags().String(flagCacheTTL, "2s", cacheTTLUsage)
	cmd.Flags().String(flagTLSMode, string(tlsclient.Correct), tlsModeUsage)
	cmd.Flags().Int(flagPort, 0, portUsage)
	cmd.Flags().Bool(flagQuiet, false, quietUsage)
	cmd.Flags().Bool(flagWithDB, false, withDBUsage)
	cmd.Flags().String(flagPoolMode, rangelab.PoolUnbounded, poolModeUsage)
	cmd.Flags().String(
		flagSecretMode,
		rangelab.SecretUnchecked,
		secretModeUsage,
	)
	cmd.Flags().String(
		flagAuthzMode,
		rangelab.AuthzCollapses,
		authzModeUsage,
	)
	cmd.Flags().String(flagDNSMode, rangelab.DNSReresolve, dnsModeUsage)

	return cmd
}

// rangeModes is the per-fixture configuration one `range up` carries. Grouped
// because four of them are now passed through two functions, and a fifth
// positional string is how two of them end up swapped.
type rangeModes struct {
	pool   string
	secret string
	authz  string
	dns    string
}

// mintRangeSecrets gives the range a fresh nonce and a fresh database password
// per `range up`. One that outlived the range would let anything that had seen
// it arm the resolver, and a credential written into a public compose file is a
// credential forever.
func mintRangeSecrets(lab *rangelab.Lab) error {
	secrets := make([]string, 0, mintedSecrets)

	for range mintedSecrets {
		secret, err := newNonce()
		if err != nil {
			return err
		}
		secrets = append(secrets, secret)
	}

	lab.ResolverNonce = secrets[0]

	// Two database secrets, never one: the administrative credential khaos
	// performs a rotation WITH must not be the credential it rotates.
	lab.DBPassword = secrets[1]
	lab.DBAppPassword = secrets[2]

	// The HMAC secret the environment fixture verifies with. The file fixture
	// gets its own from the range IMAGE, because a volume seeded from the
	// image is what lets it be mounted read-only.
	lab.SecretValue = secrets[3]

	// The control gateway's signing key. It authenticates by SIGNATURE rather
	// than from a set it remembers, because the cold-start experiment restarts
	// it: an in-memory set is empty afterwards, every credential khaos holds
	// reads as unknown, and the run measures the restart instead of the
	// policy. Measured on a live range before this key existed.
	lab.ControlSecret = secrets[4]

	return nil
}

// knownPoolModes is validated against the whole set and an unknown value is
// refused by name, because one that silently left the fixture on its default
// would report every pooled experiment against a stack that was not carrying
// the configuration it was asked for.
// knownSecretModes is validated against the whole set, because a typo that
// left the fixture on its default would report every secret experiment against
// a stack that was not carrying the configuration it was asked for.
func knownSecretModes() []string {
	return []string{rangelab.SecretValidated, rangelab.SecretUnchecked}
}

func knownPoolModes() []string {
	return []string{
		rangelab.PoolUnbounded,
		rangelab.PoolBounded,
		rangelab.PoolHeld,
	}
}

// knownAuthzModes is validated against the whole set for the same reason as
// the other three: `collapses` is the DEFAULT here, so a typo would hand the
// experiment a correct caller and report the defect as absent.
// knownDNSModes is validated by name for the same reason as the rest: the
// default leaves the gateway re-resolving, so a typo would hand `dns.ttl_rotate`
// the one target shape that always follows a rotation and the pinning direction
// would never be measured.
// reresolveFor turns the mode into the value the gateway's own environment
// carries, which is a bare boolean string the fixture reads.
func reresolveFor(mode string) string {
	if mode == rangelab.DNSPinned {
		return "false"
	}

	return "true"
}

func knownDNSModes() []string {
	return []string{rangelab.DNSReresolve, rangelab.DNSPinned}
}

func knownAuthzModes() []string {
	return []string{
		rangelab.AuthzDistinguishes,
		rangelab.AuthzCollapses,
		rangelab.AuthzRetries,
		rangelab.AuthzCached,
	}
}

func newRangeDownCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "down",
		Short: downShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lab, err := rangelab.Locate(rangelab.Ports{})
			if err != nil {
				return err
			}

			work, err := workspace.OpenExclusive(cmd.Context())
			if err != nil {
				return err
			}
			defer work.Close()

			if err := lab.Down(cmd.Context(), io.Discard); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out)
			say(out, msgRangeDown)
			fmt.Fprintln(out)

			return nil
		},
	}
}

func newRangeStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: statusShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRangeStatus(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// knownFailModes is every value the range answers to. An unrecognised one
// would leave EVERY gateway behaving correctly, so a typo is refused by name.
func knownFailModes() []string {
	modes := []string{
		rangelab.FailModeShut,
		rangelab.FailModeOpen,
		rangelab.FailModeStaleRearm,
	}

	for _, mode := range verifier.Modes() {
		if !slices.Contains(modes, mode) {
			modes = append(modes, mode)
		}
	}

	return modes
}

// validateModes refuses an unknown value for any of the three, by name. One
// flag drives every gateway and an unrecognised value would leave the whole
// range behaving CORRECTLY, which makes a typo the worst possible outcome: the
// stack comes up, nothing is broken, and every experiment reports a clean
// survival against a fixture that was supposed to carry the bug.
func validateModes(failMode string, modes rangeModes) error {
	if !slices.Contains(knownFailModes(), failMode) {
		return fmt.Errorf(errUnknownFailMode, ErrUnknownFailMode, failMode,
			strings.Join(knownFailModes(), listSep))
	}

	if !slices.Contains(knownPoolModes(), modes.pool) {
		return fmt.Errorf(errUnknownPoolMode, ErrUnknownPoolMode, modes.pool,
			strings.Join(knownPoolModes(), listSep))
	}

	if !slices.Contains(knownSecretModes(), modes.secret) {
		return fmt.Errorf(errUnknownSecretMode, ErrUnknownSecretMode,
			modes.secret, strings.Join(knownSecretModes(), listSep))
	}

	if !slices.Contains(knownAuthzModes(), modes.authz) {
		return fmt.Errorf(errUnknownAuthzMode, ErrUnknownAuthzMode,
			modes.authz, strings.Join(knownAuthzModes(), listSep))
	}

	if !slices.Contains(knownDNSModes(), modes.dns) {
		return fmt.Errorf(errUnknownDNSMode, ErrUnknownDNSMode,
			modes.dns, strings.Join(knownDNSModes(), listSep))
	}

	return nil
}

// alsoBoundOn is every address BESIDES loopback that a port has to be free on.
// Four of the tiers bind the Docker bridge gateway rather than loopback, so a
// port khaos proved free on 127.0.0.1 can still be taken where they will bind
// it. A daemon that will not answer is not fatal: the free check degrades to
// loopback and the tier's own bind refusal names the port.
func alsoBoundOn(ctx context.Context, work *workspace.Workspace) []string {
	gateway, err := work.Docker.BridgeGateway(ctx)
	if err != nil {
		return nil
	}

	return []string{gateway}
}

// sayRangeIsUp is the operator-facing summary, split out so the function that
// builds the range is about building it.
func sayRangeIsUp(out io.Writer, failMode string, port int, withDB bool) {
	event(out, markOK, theme.StatusOK, msgRangeUp)
	note(out, fmt.Sprintf(msgFailMode, failMode))
	note(out, fmt.Sprintf(msgPortHint, port))

	if withDB {
		note(out, msgStatefulUp)
	}

	note(out, msgTokenHint)
	fmt.Fprintln(out)
}

func runRangeUp(
	ctx context.Context,
	out io.Writer,
	failMode, cacheTTL, tlsMode string,
	port int,
	quiet, withDB bool,
	modes rangeModes,
) error {
	if err := validateModes(failMode, modes); err != nil {
		return err
	}

	// Refused here because the container has nobody to return an error to.
	if _, err := tlsclient.ParseMode(tlsMode); err != nil {
		return err
	}

	work, err := workspace.OpenExclusive(ctx)
	if err != nil {
		return err
	}
	defer work.Close()
	if err := work.RequireClean(); err != nil {
		return err
	}

	progress := io.Writer(os.Stderr)
	if quiet {
		progress = io.Discard
	}

	fmt.Fprintln(out)
	say(out, msgStarting)

	pinned := port != 0
	var lab rangelab.Lab

	also := alsoBoundOn(ctx, work)

	for attempt := range portAttempts {
		// Only the direct gateway's port is pinnable; the others are plumbing.
		ports, err := rangelab.FreePorts(also...)
		if err != nil {
			return err
		}

		if pinned {
			ports.Gateway = port
		}
		port = ports.Gateway

		lab, err = rangelab.Locate(ports)
		if err != nil {
			return err
		}

		if err := mintRangeSecrets(&lab); err != nil {
			return err
		}

		err = lab.Up(
			ctx,
			progress,
			failMode,
			cacheTTL,
			tlsMode,
			modes.pool,
			modes.secret,
			modes.authz,
			reresolveFor(modes.dns),
			withDB,
		)
		if err == nil {
			break
		}

		if pinned || !rangelab.PortTaken(err) || attempt == portAttempts-1 {
			return fmt.Errorf(errPortBound, port, err)
		}

		note(out, fmt.Sprintf(msgPortRetry, port))
	}

	sayRangeIsUp(out, failMode, lab.Port, withDB)

	// Read back from the containers, which are the only authority on where
	// they will actually dial and which issuer they will trust.
	describeEntryPoints(ctx, out, work.Docker)

	return nil
}

func runRangeStatus(ctx context.Context, out io.Writer) error {
	work, err := workspace.OpenShared(ctx)
	if err != nil {
		return err
	}
	defer work.Close()

	targets, err := work.Docker.Targets(
		ctx,
		dockerx.Filter{Project: rangelab.ProjectName},
	)
	if err != nil {
		return err
	}

	fmt.Fprintln(out)

	if len(targets) == 0 {
		note(out, msgRangeStopped)
		fmt.Fprintln(out)
		return nil
	}

	for _, target := range targets {
		status := theme.Fg(theme.StatusOK, statusReady)
		if refusal := dockerx.Refuse(target, dockerx.Guard{}); refusal != nil {
			status = theme.Fg(theme.StatusWarn, refusal.Predicate)
		}

		fmt.Fprintf(out, rowLayout, render.Indent,
			theme.Fg(theme.TextBright, render.Cell(target.Name, colName)),
			theme.Fg(theme.TextNormal, render.Cell(target.Project, colProject)),
			theme.Fg(theme.TextDim, render.Cell(target.Image, colImage)),
			status)
	}

	fmt.Fprintln(out)

	// The container listing says nothing about which tier is reached how.
	describeEntryPoints(ctx, out, work.Docker)

	return nil
}

func describeEntryPoints(
	ctx context.Context,
	out io.Writer,
	reader rangelab.PortReader,
) {
	lab, err := rangelab.Discover(ctx, reader)
	if err != nil {
		return
	}

	say(out, fmt.Sprintf(msgTierDirect, lab.ProtectedURL()))

	if lab.ProxiedPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierProxied,
				lab.ProxiedProtectedURL(),
				lab.ProxyPort,
			),
		)
	}

	if lab.VerifierPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierVerifier,
				lab.VerifierProtectedURL(),
				lab.Issuer,
			),
		)
	}

	if lab.TLSPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierTLS,
				lab.TLSProtectedURL(),
				lab.Dependency,
				lab.TLSMode,
			),
		)
	}

	if lab.DNSPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierDNS,
				lab.DNSProtectedURL(),
				rangelab.DNSDependencyName,
				rangelab.ResolverAddress,
			),
		)
	}

	if lab.AuthzPort != 0 {
		say(
			out,
			fmt.Sprintf(
				msgTierAuthz,
				lab.AuthzProtectedURL(),
				lab.AuthzBase,
			),
		)
	}

	fmt.Fprintln(out)
}
