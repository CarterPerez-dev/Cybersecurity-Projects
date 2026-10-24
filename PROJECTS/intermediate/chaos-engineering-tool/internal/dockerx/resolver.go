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
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const (
	// These labels let an orphan survive khaos's death and be reclaimed by
	// label rather than by khaos remembering what it started.
	ResolverLabel        = "khaos.resolver"
	ResolverNetworkLabel = "khaos.resolver.network"
	ResolverNonceLabel   = "khaos.resolver.nonce"
	ResolverValue        = "true"

	// The tag carries a digest of khaos's binary, so a rebuilt khaos imports a
	// new image instead of running the previous build's resolver.
	ResolverImagePrefix = "khaos-dnsrv"

	ResolverEntrypoint = "/khaos"
	ResolverCommand    = "serve-resolver"

	// Where the control nonce travels; see resolverArgs for why not a flag.
	EnvResolverNonce = "KHAOS_RESOLVER_NONCE"

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

	dynamicSelfFix = "khaos imports its OWN binary as a one-layer container image with no base, and two tiers need that: `khaos resolver up`, because an unprivileged process cannot bind port 53 and Docker's --dns carries an address with no port, and the `credential.secret_file_` faults, because read-only is a property of the target's mount rather than of the volume and only a helper mounting it read-write can reach a `:ro` secret. A base-less image carries no shared libraries, so the binary has to be statically linked and this one is not. Rebuild with CGO_ENABLED=0 (the justfile and the release builds both do), or install the released binary. Running `dns.` experiments against a resolver that already exists, including the range's, does not need this, and no other family needs it at all"

	filterLabelKey = "label"
)

var ErrDynamicSelf = errors.New(
	"this khaos binary is dynamically linked and cannot be its own container image",
)

var ErrResolverNotFound = errors.New("no chaos resolver exists on that network")

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
	Network string

	// Carries the network, so two resolvers on two networks cannot collide.
	Name string

	// Stored as a LABEL as well as passed in, so khaos reads it back off the
	// container rather than remembering what it chose.
	Nonce string

	Zone map[string]string

	Control string
}

// SelfStatic refuses a khaos binary that cannot be its own container image. The
// check is on the ELF rather than a build tag because what matters is the
// artifact: cgo links libc for `net`, and that dies in a base-less image.
func SelfStatic() error {
	return staticELF(selfExe)
}

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

// ImportResolverImage builds a single-layer image out of khaos's own binary,
// with no base image, no registry and no network, because a published image
// needs a registry and building one needs a source tree khaos may not have.
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

	// Tagged by content, so a rebuilt khaos cannot run the previous resolver.
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

	// The import endpoint reports failures in the BODY rather than the status,
	// so an undrained import fails invisibly and leaves khaos creating a
	// container from an image that does not exist.
	body, err := io.ReadAll(result)
	if err != nil {
		return "", fmt.Errorf(errImportImage, tag, err)
	}

	if strings.Contains(string(body), `"error"`) {
		return "", fmt.Errorf(errImportDrain, tag, firstLine(body))
	}

	// Superseded images are removed now because nothing else ever would, and
	// failures are ignored since an image in use is refused by the daemon.
	c.pruneResolverImages(ctx, tag)

	return tag, nil
}

// pruneResolverImages has three guards, because it deletes images: only tags
// under ResolverImagePrefix, never the tag in use, and removal is not forced so
// the daemon refuses anything still referenced.
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

// RunResolver reads the address back out of the daemon rather than choosing
// one, because Docker refuses `--ip` on a network whose subnet it picked, which
// is also why arming happens in band instead of by recreating the container.
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
	} else if !errors.Is(err, ErrResolverNotFound) {
		return Resolver{}, err
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
			// Nothing is published: the resolver listens on 53 inside its own
			// namespace, which is why khaos needs no capability.
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
		return Resolver{}, c.DiscardResolver(ctx, created.ID,
			fmt.Errorf(errStartResolve, ShortID(created.ID), err))
	}

	address, err := c.NetworkAddress(ctx, created.ID, spec.Network)
	if err != nil {
		return Resolver{}, c.DiscardResolver(ctx, created.ID,
			fmt.Errorf(errResolverAddr, spec.Network, err))
	}

	return Resolver{
		ID:      created.ID,
		Name:    spec.Name,
		Network: spec.Network,
		Address: address,
		Nonce:   spec.Nonce,
	}, nil
}

func (c *Client) DiscardResolver(
	ctx context.Context,
	id string,
	cause error,
) error {
	cleanup, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), 30*time.Second,
	)
	defer cancel()
	return errors.Join(cause, c.RemoveResolver(cleanup, id))
}

// FindResolver matches by LABEL and not by name, because reclaim works from a
// cold start and a renamed resolver would otherwise be duplicated.
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

	return Resolver{}, fmt.Errorf("%w: %s", ErrResolverNotFound, networkName)
}

// Resolvers lists every chaos resolver on this daemon.
func (c *Client) Resolvers(ctx context.Context) ([]Resolver, error) {
	// label=KEY=VALUE, not label=KEY. moby's MatchKVList splits on the first
	// `=` and never compares a missing value, so a key-only filter matches
	// every container carrying the label — and RemoveResolver force-removes
	// whatever this returns.
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

		// From the daemon, not the summary: a created-but-never-started
		// resolver has no address and must report empty.
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

// RemoveResolver treats a missing container as success: the resolver went with
// it, and an error would wedge a journal record and stop `khaos reap` sweeping.
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

// resolverArgs keeps the NONCE off the command line. Everything else is an
// argument so `docker inspect` shows what the resolver was told, but
// `/proc/<pid>/cmdline` is mode 444 and readable by every local user while
// `/proc/<pid>/environ` is 400, and the nonce authorises arming and disarming.
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

// resolverEnv carries the one field that must not appear in the process table.
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

// ResolverControlName is generated when the operator named no control. It is in
// `.invalid`, reserved by RFC 2606, so it can never collide with a real name.
func ResolverControlName(networkName string) string {
	return "control." + networkName + ".khaos.invalid."
}

// ResolverControlURL is on the container's own address, which the host routes
// to directly, so nothing is ever published.
func ResolverControlURL(address string) string {
	return fmt.Sprintf("http://%s:%d", address, dnsrv.ControlPort)
}
