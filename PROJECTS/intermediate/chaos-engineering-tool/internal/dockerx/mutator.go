// ©AngelaMos | 2026
// mutator.go

package dockerx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

const (
	MutatorLabel = "khaos.mutator"
	MutatorValue = "true"
	MutatorRun   = "khaos.mutator.run"

	// MutatorNonce authorises the subcommand this container runs. The command
	// writes to a path it is given, so on the HOST it must refuse: khaos never
	// writes host-global state, and a command that would truncate any file it
	// is pointed at cannot be reachable by accident.
	MutatorNonce = "KHAOS_MUTATOR_NONCE"

	mutatorPrefix     = "khaos-mutator-"
	mutatorNetwork    = "none"
	mutatorWait       = 30 * time.Second
	logTail           = "20"
	mutatorNonceBytes = 6

	capAll         = "ALL"
	capDACOverride = "DAC_OVERRIDE"
	capFileOwner   = "FOWNER"

	errMutatorCreate = "create the mutator container for %s: %w"
	errMutatorStart  = "start the mutator container for %s: %w"
	errMutatorWait   = "wait for the mutator container for %s: %w"
	errMutatorFailed = "the mutator container exited %d: %s"
	errNoMount       = "%w: %s is not inside any mount of %s, so khaos cannot reach it from a helper and could not restore it from a cold start either. Deliver the secret on a volume or a bind-mounted directory"
	errStatSecret    = "read %s back from the container: %w"
	errTmpfsMount    = "%w: %s is on a tmpfs mount, which is private to the container, so khaos can neither reach it from a helper nor put the original back after the run"
)

var ErrUnreachableSecret = errors.New(
	"that path is not somewhere khaos can act and then undo",
)

// Mount is one of the target's own mounts, read off its inspection. khaos
// replicates exactly the one containing the file it acts on, and never
// anything else the target can see.
type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadWrite   bool   `json:"read_write"`
	Name        string `json:"name,omitempty"`
}

type MutatorSpec struct {
	RunID string
	Mount Mount
	Nonce string
	Args  []string
}

// MountFor finds the mount that contains a path in the target's namespace, and
// refuses the two shapes khaos cannot act on reversibly.
func MountFor(target Target, path string) (Mount, error) {
	best := Mount{}

	for _, candidate := range target.Mounts {
		if candidate.Destination == "" {
			continue
		}
		if !within(candidate.Destination, path) {
			continue
		}
		if len(candidate.Destination) <= len(best.Destination) {
			continue
		}

		best = candidate
	}

	if best.Destination == "" {
		return Mount{}, fmt.Errorf(
			errNoMount,
			ErrUnreachableSecret,
			path,
			target.Name,
		)
	}

	// A tmpfs is private to the container's own namespace: a helper mounting
	// the same spec gets an EMPTY filesystem, so khaos would write a secret
	// into nowhere and report it as a fault that landed.
	if best.Type == tmpfsType {
		return Mount{}, fmt.Errorf(
			errTmpfsMount,
			ErrUnreachableSecret,
			path,
		)
	}

	return best, nil
}

// FileLevelMount reports whether the path IS the mount point rather than a file
// inside it. Renaming a mount point is impossible, which is the one mutation
// khaos has to refuse on that shape rather than approximate.
func FileLevelMount(m Mount, path string) bool {
	return m.Destination == path
}

func within(dir, path string) bool {
	if dir == path {
		return true
	}

	if !strings.HasSuffix(dir, pathSeparator) {
		dir += pathSeparator
	}

	return strings.HasPrefix(path, dir)
}

// RunMutator creates the container, waits for it, and removes it. The exit code
// is read from the daemon rather than from the logs, and a non-zero one carries
// the container's own output, because a mutation that failed silently would
// leave khaos measuring an unfaulted target.
func (c *Client) RunMutator(
	ctx context.Context,
	spec MutatorSpec,
) (string, error) {
	image, err := c.ImportResolverImage(ctx)
	if err != nil {
		return "", err
	}

	suffix, err := mutatorSuffix()
	if err != nil {
		return "", err
	}

	name := mutatorPrefix + suffix

	created, err := c.api.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: name,
		Config: &container.Config{
			Image: image,
			Cmd:   spec.Args,
			Env:   []string{MutatorNonce + "=" + spec.Nonce},
			Labels: map[string]string{
				MutatorLabel: MutatorValue,
				MutatorRun:   spec.RunID,
			},
		},
		HostConfig: &container.HostConfig{
			// Read-write regardless of how the TARGET mounts it: read-only is
			// a property of the target's mount and not of the volume, which is
			// what makes a helper the only route to a `:ro` secret.
			Mounts: []mount.Mount{{
				Type:     mount.Type(spec.Mount.Type),
				Source:   mutatorSource(spec.Mount),
				Target:   spec.Mount.Destination,
				ReadOnly: false,
			}},
			NetworkMode: mutatorNetwork,

			// ALL dropped, then exactly two added back, and the pair is the
			// whole privilege this tier holds. A secret is conventionally
			// delivered mode 0400 owned by the service's own uid, and root
			// ignores a mode only because of DAC_OVERRIDE: measured, a helper
			// that dropped ALL could not open the range's own secret and
			// reported `permission denied` as root. FOWNER is what lets it
			// chmod a file it does not own, which the unreadable fault is.
			//
			// Neither reaches outside this container: it joins no network,
			// mounts one volume, and exits. The alternative was a
			// world-readable secret in the fixture, which would have made the
			// fixture unlike every real one.
			CapDrop: []string{capAll},
			CapAdd:  []string{capDACOverride, capFileOwner},
			RestartPolicy: container.RestartPolicy{
				Name: container.RestartPolicyDisabled,
			},
		},
		NetworkingConfig: &network.NetworkingConfig{},
	})
	if err != nil {
		return "", fmt.Errorf(errMutatorCreate, spec.Mount.Destination, err)
	}

	defer func() { _ = c.RemoveMutator(context.WithoutCancel(ctx), created.ID) }()

	if _, err := c.api.ContainerStart(
		ctx,
		created.ID,
		client.ContainerStartOptions{},
	); err != nil {
		return "", fmt.Errorf(errMutatorStart, spec.Mount.Destination, err)
	}

	code, err := c.awaitMutator(ctx, created.ID)
	if err != nil {
		return "", fmt.Errorf(errMutatorWait, spec.Mount.Destination, err)
	}

	output := c.mutatorLogs(ctx, created.ID)

	if code != 0 {
		return output, fmt.Errorf(errMutatorFailed, code, output)
	}

	return output, nil
}

// mutatorSource is the volume NAME for a volume mount and the host path for a
// bind, which is what the daemon expects for each.
// mutatorSuffix keeps two mutators in one run from colliding on a name, which
// a run id alone does not: a revert creates a second one.
func mutatorSuffix() (string, error) {
	buffer := make([]byte, mutatorNonceBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return hex.EncodeToString(buffer), nil
}

func mutatorSource(m Mount) string {
	if m.Type == string(mount.TypeVolume) && m.Name != "" {
		return m.Name
	}

	return m.Source
}

func (c *Client) awaitMutator(
	ctx context.Context,
	containerID string,
) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, mutatorWait)
	defer cancel()

	waiting := c.api.ContainerWait(
		ctx,
		containerID,
		client.ContainerWaitOptions{
			Condition: container.WaitConditionNotRunning,
		},
	)

	select {
	case result := <-waiting.Result:
		if result.Error != nil {
			return result.StatusCode, errors.New(result.Error.Message)
		}
		return result.StatusCode, nil
	case err := <-waiting.Error:
		return 0, err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (c *Client) mutatorLogs(ctx context.Context, containerID string) string {
	logs, err := c.api.ContainerLogs(
		ctx,
		containerID,
		client.ContainerLogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Tail:       logTail,
		},
	)
	if err != nil {
		return ""
	}
	defer func() { _ = logs.Close() }()

	body, err := io.ReadAll(logs)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(printable(string(body)))
}

// printable strips the stream multiplexing header bytes the daemon prefixes
// each log frame with, so a refusal reads as a sentence.
func printable(raw string) string {
	var out strings.Builder

	for _, r := range raw {
		if r == '\n' || r == '\t' || (r >= ' ' && r != '\x7f') {
			out.WriteRune(r)
		}
	}

	return out.String()
}

func (c *Client) RemoveMutator(ctx context.Context, containerID string) error {
	_, err := c.api.ContainerRemove(
		ctx,
		containerID,
		client.ContainerRemoveOptions{Force: true},
	)

	return err
}

// Mutators lists the helper containers khaos has left behind. Filtered by
// label=KEY=VALUE, never label=KEY: moby's MatchKVList splits on the first `=`
// and never compares a missing value, and this list is what a reclaim would
// force-remove.
func (c *Client) Mutators(ctx context.Context) ([]string, error) {
	summaries, err := c.list(
		ctx,
		make(client.Filters).Add(
			filterLabelKey,
			MutatorLabel+"="+MutatorValue,
		),
	)
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(summaries))
	for _, summary := range summaries {
		ids = append(ids, summary.ID)
	}

	slices.Sort(ids)

	return ids, nil
}

// SecretStat is the TARGET's own view of a file, read through the archive
// endpoint's HEAD. It is the confirmation read-back for every secret fault:
// the mutator writes through a helper, and this is khaos asking the container
// under test what it now has. Measured to work on every mount shape, including
// the one the archive API cannot write.
type SecretStat struct {
	Exists bool
	Size   int64
	Mode   uint32
	Link   string
}

// StatSecret never turns a missing file into an error, because absence is one
// of the four faults and has to be reportable as an observation.
func (c *Client) StatSecret(
	ctx context.Context,
	containerID, path string,
) (SecretStat, error) {
	result, err := c.api.ContainerStatPath(
		ctx,
		containerID,
		client.ContainerStatPathOptions{Path: path},
	)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return SecretStat{}, nil
		}

		return SecretStat{}, fmt.Errorf(errStatSecret, path, c.classify(err))
	}

	return SecretStat{
		Exists: true,
		Size:   result.Stat.Size,
		Mode:   uint32(result.Stat.Mode),
		Link:   result.Stat.LinkTarget,
	}, nil
}
