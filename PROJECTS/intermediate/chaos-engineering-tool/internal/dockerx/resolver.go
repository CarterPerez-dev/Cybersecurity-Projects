// ©AngelaMos | 2026
// resolver.go

package dockerx

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const (
	// ResolverLabel marks a container khaos created to serve DNS, and
	// ResolverNetworkLabel records which network it serves. Both exist so an
	// orphan survives khaos's death and is reclaimable by label rather than by
	// khaos remembering what it started, which is the same rule the netem
	// sidecar tier is held to.
	ResolverLabel        = "khaos.resolver"
	ResolverNetworkLabel = "khaos.resolver.network"
	ResolverNonceLabel   = "khaos.resolver.nonce"
	ResolverValue        = "true"

	// ResolverImagePrefix tags the image khaos imports from its own binary. The
	// tag carries a digest of that binary, so a rebuilt khaos imports a new
	// image instead of silently running the previous build's resolver — which
	// would be a resolver whose code does not match the khaos interpreting it.
	ResolverImagePrefix = "khaos-dnsrv"

	// ResolverEntrypoint is where khaos's own binary lands inside the image, and
	// ResolverCommand is the hidden subcommand it is started with.
	ResolverEntrypoint = "/khaos"
	ResolverCommand    = "serve-resolver"

	// EnvResolverNonce is where the control nonce travels. See resolverArgs for
	// why it is not a flag.
	EnvResolverNonce = "KHAOS_RESOLVER_NONCE"

	// resolverBinaryMode is executable and not writable. The image has exactly
	// one file in it and nothing in the container can replace it.
	resolverBinaryMode = 0o555

	digestLength = 12
	selfExe      = "/proc/self/exe"
)

const (
	errReadSelf       = "read khaos's own binary at %s: %w"
	errDynamicSelf    = "%w: %s"
	errTarSelf        = "build the resolver image layer: %w"
	errImportImage    = "import the resolver image %s: %w"
	errImportDrain    = "import the resolver image %s: the daemon reported: %s"
	errCreateResolve  = "create the chaos resolver container on %s: %w"
	errStartResolve   = "start the chaos resolver container %s: %w"
	errResolverAddr   = "read the chaos resolver's address on %s: %w"
	errListResolvers  = "list khaos's resolver containers: %w"
	errResolverExists = "%w: %s already serves DNS for %s"

	// A dynamically linked khaos cannot BUILD a resolver image, and drives one
	// that already exists perfectly well, so the refusal says which of the two
	// it is.
	dynamicSelfFix = "`khaos resolver up` imports khaos's own binary as a one-layer container image with no base, because an unprivileged process cannot bind port 53 and Docker's --dns carries an address with no port, so the binary has to be statically linked. This one is dynamically linked and would fail to exec with no shared libraries to find. Rebuild with CGO_ENABLED=0 (the justfile and the release builds both do), or install the released binary. Running `dns.` experiments against a resolver that already exists, including the range's, does not need this"

	filterLabelKey = "label"
)

var ErrDynamicSelf = errors.New(
	"this khaos binary is dynamically linked and cannot be its own container image",
)

var ErrResolverExists = errors.New(
	"a khaos resolver is already serving that network",
)

// Resolver is a running chaos resolver container, as khaos addresses it.
type Resolver struct {
	ID      string
	Name    string
	Network string
	Address string
	Nonce   string
}

// ResolverSpec is what khaos needs to stand one up.
type ResolverSpec struct {
	// Network is the target's network. The resolver joins it so the target can
	// reach it by address with no published host port at all.
	Network string

	// Name is the container name, which carries the network so two resolvers on
	// two networks cannot collide.
	Name string

	// Nonce authorises the resolver's control surface and is stored as a LABEL
	// as well as passed as an argument, so khaos reads it back off the container
	// rather than remembering what it chose.
	Nonce string

	// Zone is the names the resolver is authoritative for, each mapped to its
	// honest address, passed as `name=address` arguments.
	Zone map[string]string

	// Control is the zone name no fault ever touches.
	Control string
}

// SelfStatic refuses a khaos binary that cannot be its own container image.
//
// The check is on the ELF rather than on a build tag, because what matters is
// the artifact: `go build` with cgo available links libc for `net`, and the
// resulting binary in a base-less image dies looking for
// `/lib64/ld-linux-x86-64.so.2`. Measured on this host before the tier was
// built.
func SelfStatic() error {
	return staticELF(selfExe)
}

// staticELF is split out from SelfStatic so it can be given a two-sided
// control. A guard that decides whether a whole command works needs an input it
// MUST reject, and `/proc/self/exe` inside a test is whatever `go test` built,
// which is not a value a test gets to choose.
func staticELF(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf(errReadSelf, path, err)
	}
	defer func() { _ = file.Close() }()

	for _, prog := range file.Progs {
		if prog.Type == elf.PT_INTERP {
			return fmt.Errorf(errDynamicSelf, ErrDynamicSelf, dynamicSelfFix)
		}
	}

	return nil
}

// ImportResolverImage builds a single-layer image out of khaos's own binary and
// imports it, with no base image, no registry and no network.
//
// This is what keeps the DNS tier keyless. The alternative shapes were all
// worse: a published image needs a registry and drifts out of step with the CLI
// that drives it, and building one needs the source tree, which a curl-installed
// khaos does not have. A one-file tar through the import endpoint needs nothing
// that is not already on the machine.
//
// The image is khaos's ENTIRE binary, around 24 MB, so the resolver container
// carries the whole CLI as its entrypoint. That is the price of there being no
// second artifact to build, version and keep in step with the CLI driving it.
func (c *Client) ImportResolverImage(ctx context.Context) (string, error) {
	if err := SelfStatic(); err != nil {
		return "", err
	}

	binary, err := os.ReadFile(selfExe)
	if err != nil {
		return "", fmt.Errorf(errReadSelf, selfExe, err)
	}

	digest := sha256.Sum256(binary)
	tag := ResolverImagePrefix + ":" +
		hex.EncodeToString(digest[:])[:digestLength]

	// Tagged by content, so a khaos that has run before reuses its image and a
	// rebuilt khaos cannot run the previous build's resolver.
	if have, err := c.hasImage(ctx, tag); err == nil && have {
		return tag, nil
	}

	layer, err := tarSingleFile(ResolverEntrypoint, binary)
	if err != nil {
		return "", fmt.Errorf(errTarSelf, err)
	}

	result, err := c.api.ImageImport(
		ctx,
		client.ImageImportSource{
			Source:     bytes.NewReader(layer),
			SourceName: "-",
		},
		tag,
		client.ImageImportOptions{
			Changes: []string{
				`ENTRYPOINT ["` + ResolverEntrypoint + `"]`,
			},
		},
	)
	if err != nil {
		return "", fmt.Errorf(errImportImage, tag, err)
	}
	defer func() { _ = result.Close() }()

	// The import endpoint streams progress and reports failures in the BODY
	// rather than in the status, so an import that is never drained can fail
	// invisibly and leave khaos creating a container from an image that does not
	// exist.
	body, err := io.ReadAll(result)
	if err != nil {
		return "", fmt.Errorf(errImportImage, tag, err)
	}

	if strings.Contains(string(body), `"error"`) {
		return "", fmt.Errorf(errImportDrain, tag, firstLine(body))
	}

	// Every superseded resolver image is removed now, because nothing else ever
	// would. The tag carries a digest of khaos's binary, so each rebuild of
	// khaos creates a NEW image and leaves the previous one behind: measured at
	// 24.4MB each, and khaos is rebuilt on every `just build`. On a machine that
	// also serves live traffic, litter khaos creates and never collects is
	// khaos's problem rather than the operator's.
	//
	// Failures are deliberately ignored. An image somebody else is using is
	// refused by the daemon, which is the behaviour wanted, and a resolver that
	// imported correctly must not fail because tidying up afterwards did not.
	c.pruneResolverImages(ctx, tag)

	return tag, nil
}

// pruneResolverImages removes khaos's own resolver images except the one just
// imported.
//
// Three guards, because this deletes images. Only tags under
// ResolverImagePrefix are candidates, so nothing khaos did not create can be
// reached; the tag in use is excluded by name; and removal is not forced, so the
// daemon refuses any image a container still references rather than khaos
// deciding it is safe.
func (c *Client) pruneResolverImages(ctx context.Context, keep string) {
	result, err := c.api.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		return
	}

	for _, image := range result.Items {
		for _, tag := range image.RepoTags {
			if tag == keep ||
				!strings.HasPrefix(tag, ResolverImagePrefix+":") {
				continue
			}

			_, _ = c.api.ImageRemove(ctx, tag, client.ImageRemoveOptions{})
		}
	}
}

func (c *Client) hasImage(ctx context.Context, tag string) (bool, error) {
	result, err := c.api.ImageList(ctx, client.ImageListOptions{})
	if err != nil {
		return false, err
	}

	for _, image := range result.Items {
		if slices.Contains(image.RepoTags, tag) {
			return true, nil
		}
	}

	return false, nil
}

// RunResolver creates and starts a chaos resolver on a network and reads its
// address back out of the daemon.
//
// The address is read back rather than chosen, because Docker refuses `--ip` on
// a network whose subnet it picked: "user specified IP address is supported only
// when connecting to networks with user configured subnets". That measurement is
// also why arming is in band — a resolver that had to be recreated to be armed
// would move the address the target was created to dial.
func (c *Client) RunResolver(
	ctx context.Context,
	spec ResolverSpec,
) (Resolver, error) {
	if existing, err := c.FindResolver(ctx, spec.Network); err == nil {
		return Resolver{}, fmt.Errorf(
			errResolverExists,
			ErrResolverExists,
			existing.Name,
			spec.Network,
		)
	}

	image, err := c.ImportResolverImage(ctx)
	if err != nil {
		return Resolver{}, err
	}

	created, err := c.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: spec.Name,
		Config: &container.Config{
			Image: image,
			Cmd:   resolverArgs(spec),
			Env:   resolverEnv(spec),
			Labels: map[string]string{
				ResolverLabel:        ResolverValue,
				ResolverNetworkLabel: spec.Network,
				ResolverNonceLabel:   spec.Nonce,
			},
		},
		HostConfig: &container.HostConfig{
			// Nothing is published. The resolver listens on 53 inside its own
			// network namespace, which is the entire reason khaos holds no
			// capability: an unprivileged host process cannot bind 53 at all.
			RestartPolicy: container.RestartPolicy{
				Name: container.RestartPolicyDisabled,
			},
		},
		NetworkingConfig: &network.NetworkingConfig{
			EndpointsConfig: map[string]*network.EndpointSettings{
				spec.Network: {},
			},
		},
	})
	if err != nil {
		return Resolver{}, fmt.Errorf(errCreateResolve, spec.Network, err)
	}

	if _, err := c.api.ContainerStart(
		ctx,
		created.ID,
		client.ContainerStartOptions{},
	); err != nil {
		// A container that will not start is removed rather than left behind.
		// The daemon accepts a DNS entry it will later refuse at start time, so
		// this path is reachable by an operator mistake and not only by a bug.
		_ = c.RemoveResolver(ctx, created.ID)
		return Resolver{}, fmt.Errorf(errStartResolve, ShortID(created.ID), err)
	}

	address, err := c.NetworkAddress(ctx, created.ID, spec.Network)
	if err != nil {
		_ = c.RemoveResolver(ctx, created.ID)
		return Resolver{}, fmt.Errorf(errResolverAddr, spec.Network, err)
	}

	return Resolver{
		ID:      created.ID,
		Name:    spec.Name,
		Network: spec.Network,
		Address: address,
		Nonce:   spec.Nonce,
	}, nil
}

// FindResolver looks for a resolver khaos already has on a network, by LABEL.
//
// By label and not by name, because reclaim has to work from a cold start where
// khaos remembers nothing, and because an operator who renamed one would
// otherwise get a second resolver on the same network with the target pointed at
// whichever one it was created against.
func (c *Client) FindResolver(
	ctx context.Context,
	networkName string,
) (Resolver, error) {
	resolvers, err := c.Resolvers(ctx)
	if err != nil {
		return Resolver{}, err
	}

	for _, resolver := range resolvers {
		if resolver.Network == networkName {
			return resolver, nil
		}
	}

	return Resolver{}, fmt.Errorf(errNoMatch, networkName)
}

// Resolvers lists every chaos resolver on this daemon, which is what `khaos
// reclaim` sweeps and what `khaos doctor` reports.
func (c *Client) Resolvers(ctx context.Context) ([]Resolver, error) {
	// label=KEY=VALUE, not label=KEY. moby's MatchKVList splits on the first
	// `=` and never compares the value when there is none, so the key-only
	// filter matched every container carrying the label whatever it said —
	// demonstrated with `com.docker.compose.project`, which returned 135
	// containers across every distinct project value.
	//
	// That mattered because `RemoveResolver` FORCE-removes what this returns. A
	// container labelled `khaos.resolver=false`, or labelled by somebody else
	// entirely, was listed, adopted as khaos's own authority, and removable.
	// The consent label has `checkConsentNotTrue` for exactly this reason;
	// this tier took the loose filter and skipped the compensating check.
	result, err := c.api.ContainerList(ctx, client.ContainerListOptions{
		All: true,
		Filters: make(client.Filters).Add(
			filterLabelKey,
			ResolverLabel+"="+ResolverValue,
		),
	})
	if err != nil {
		return nil, fmt.Errorf(errListResolvers, err)
	}

	out := make([]Resolver, 0, len(result.Items))

	for _, summary := range result.Items {
		networkName := summary.Labels[ResolverNetworkLabel]

		resolver := Resolver{
			ID:      summary.ID,
			Name:    containerName(summary.Names),
			Network: networkName,
			Nonce:   summary.Labels[ResolverNonceLabel],
		}

		// The address comes from the daemon rather than from the summary,
		// because a created-but-never-started resolver has none and has to
		// report empty rather than a stale value from somewhere else.
		if address, err := c.NetworkAddress(
			ctx,
			summary.ID,
			networkName,
		); err == nil {
			resolver.Address = address
		}

		out = append(out, resolver)
	}

	return out, nil
}

// RemoveResolver takes the container away. A missing container is success: the
// resolver provably went with it, and reporting that as a failure would wedge a
// journal record forever and, because `khaos reap` stops on a sweep error,
// disable the dead man's switch for every other fault on the machine.
func (c *Client) RemoveResolver(ctx context.Context, containerID string) error {
	_, err := c.api.ContainerRemove(
		ctx,
		containerID,
		client.ContainerRemoveOptions{
			Force: true,
		},
	)

	if err != nil && errors.Is(c.classify(err), ErrContainerGone) {
		return nil
	}

	return err
}

// resolverArgs is the command line the container runs, and the NONCE is
// deliberately not on it.
//
// Everything else is an argument, because `docker inspect` then shows exactly
// what the resolver was told and that is how khaos reads its own configuration
// back instead of remembering it. The nonce is the one field that is a secret,
// and a command line is the leakiest place to put one: measured on this host,
// `/proc/<pid>/cmdline` is mode 444 and readable by every local user, while
// `/proc/<pid>/environ` is 400. Both are equally visible through `docker
// inspect`, which already needs socket access that is root-equivalent anyway,
// so the environment satisfies the read-back reason without the leak.
//
// What the leak buys an attacker is not academic: the nonce is the sole
// authorisation for arming and disarming khaos's DNS faults, so any local user
// could `POST /disarm` after khaos confirmed a fault and khaos would measure an
// unfaulted window and report a verdict it never earned.
func resolverArgs(spec ResolverSpec) []string {
	args := []string{
		ResolverCommand,
		"--control", spec.Control,
	}

	for _, name := range sortedKeys(spec.Zone) {
		args = append(args, "--zone", name+"="+spec.Zone[name])
	}

	return args
}

// resolverEnv carries the one field that must not appear in the host's process
// table.
func resolverEnv(spec ResolverSpec) []string {
	return []string{EnvResolverNonce + "=" + spec.Nonce}
}

func sortedKeys(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

func containerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func firstLine(payload []byte) string {
	text := strings.TrimSpace(string(payload))
	if index := strings.IndexByte(text, '\n'); index > 0 {
		return text[:index]
	}
	return text
}

// tarSingleFile builds the one-entry layer the import endpoint consumes.
func tarSingleFile(name string, content []byte) ([]byte, error) {
	var buffer bytes.Buffer

	writer := tar.NewWriter(&buffer)

	if err := writer.WriteHeader(&tar.Header{
		Name: strings.TrimPrefix(name, "/"),
		Mode: resolverBinaryMode,
		Size: int64(len(content)),
	}); err != nil {
		return nil, err
	}

	if _, err := writer.Write(content); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// ResolverControlName is the confirmation control khaos generates when the
// operator did not name one. It is in `.invalid`, which RFC 2606 reserves, so
// it can never collide with a real name the target needs and can never resolve
// anywhere but khaos's own resolver.
func ResolverControlName(networkName string) string {
	return "control." + networkName + ".khaos.invalid."
}

// ResolverControlURL is the resolver's control surface on its own container
// address. Nothing is published to the host; the host simply routes to
// container addresses on a bridge network, which is what lets khaos arm its
// resolver without a single host port.
func ResolverControlURL(address string) string {
	return fmt.Sprintf("http://%s:%d", address, dnsrv.ControlPort)
}
