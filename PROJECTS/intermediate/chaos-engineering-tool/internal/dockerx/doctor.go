// ©AngelaMos | 2026
// doctor.go

package dockerx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
)

type Status int

const (
	StatusPass Status = iota
	StatusFail
	StatusSkipped
)

type Check struct {
	Name   string
	Status Status
	Detail string
	Fix    string
}

func (c Check) OK() bool {
	return c.Status == StatusPass
}

const (
	checkEndpoint = "docker endpoint"
	checkSocket   = "socket"
	checkDaemon   = "daemon"
	checkTargets  = "consenting targets"

	// checkDNSTier is the one check whose subject is khaos's OWN binary rather
	// than the operator's Docker. `khaos resolver up` imports that binary as a
	// one-layer container image with no base, so a dynamically linked build
	// cannot CREATE a resolver — and it finds out at run time, with an error
	// about a loader path the operator never typed. `doctor` is where khaos is
	// supposed to turn that into a named cause and a fix.
	//
	// It does NOT lose the family, and the first wording of this check said it
	// did. Arming is independent of importing: a dynamically linked khaos drives
	// a resolver that already exists perfectly well, including the range's own,
	// which was measured by running `dns.nxdomain` from such a build and getting
	// a real verdict. Saying otherwise would have sent an operator to rebuild
	// over a limit they were not hitting.
	checkDNSTier = "dns tier"

	fixNoEndpoint   = "install Docker, or set DOCKER_HOST to a reachable daemon"
	fixDaemonLocal  = "start the Docker daemon: systemctl --user start docker, or sudo systemctl start docker"
	fixDaemonRemote = "check that %s is reachable and that the daemon there is listening"
	fixContext      = "run `docker context ls` to see what exists, then `docker context use <name>`, or unset DOCKER_CONTEXT"
	FixNoTargets    = "add `labels: [\"" + LabelConsent + "=" + ConsentValue + "\"]` to a service and recreate it, or run `khaos range up`"
	fixRetry        = "resolve the daemon problem above, then run this again"

	detailNoEndpoint  = "no DOCKER_HOST, no docker context, no rootless socket, no " + DockerSocketPath
	detailSkipDaemon  = "not checked, because the daemon did not answer"
	detailSocketOK    = "%s is present and a daemon is listening"
	detailDaemonOK    = "responding, API version %s"
	detailEndpointFmt = "%s (via %s%s)"
	detailTargets     = "%d container(s) carry %s=%s"
	detailNone        = "none"

	permissionFixFormat = "add yourself to the docker group and start a new login session: sudo usermod -aG docker %s. " +
		"Rootless Docker avoids this entirely and khaos prefers it, since access to %s is equivalent to root on this machine"
	fallbackUser = "your user"

	detailDNSStatic  = "khaos is statically linked, so `khaos resolver up` can build its own resolver image"
	detailDNSDynamic = "khaos is dynamically linked, so `khaos resolver up` cannot build a resolver image; %d chaos resolver(s) already running are still usable"
	detailResolvers  = "%s, and %d chaos resolver(s) are running"

	fixDNSDynamic = "rebuild with CGO_ENABLED=0 (the justfile and the release builds both do), or install the released binary. `khaos resolver up` imports khaos's own binary as a one-layer container image with no base, because an unprivileged process cannot bind port 53 and Docker's --dns carries an address with no port; a dynamically linked binary in a base-less image cannot exec. Running `dns.` experiments against a resolver that already exists, including the range's, does not need this"

	checkCapacity = 5
)

func Diagnose(ctx context.Context) []Check {
	return DiagnoseWith(ctx, os.Getenv, homeDir())
}

func DiagnoseWith(
	ctx context.Context,
	environ func(string) string,
	home string,
) []Check {
	checks := make([]Check, 0, checkCapacity)

	endpoint, err := ResolveEndpoint(environ, home)
	if err != nil {
		checks = append(checks, Check{
			Name:   checkEndpoint,
			Status: StatusFail,
			Detail: endpointFailureDetail(err),
			Fix:    endpointFix(err),
		})
		return append(
			checks,
			skipped(checkSocket),
			skipped(checkDaemon),
			skipped(checkTargets),
		)
	}

	checks = append(checks, Check{
		Name:   checkEndpoint,
		Status: StatusPass,
		Detail: fmt.Sprintf(
			detailEndpointFmt,
			endpoint.Host,
			endpoint.Source,
			contextSuffix(endpoint),
		),
	})

	path, isSocket := endpoint.SocketPath()
	if !isSocket {
		checks = append(checks, skipped(checkSocket))
	}

	cli, connectErr := Connect(ctx, endpoint)

	if isSocket {
		checks = append(checks, socketCheck(path, connectErr))
	}

	if connectErr != nil {
		checks = append(checks, Check{
			Name:   checkDaemon,
			Status: StatusFail,
			Detail: connectErr.Error(),
			Fix:    daemonFix(connectErr, endpoint),
		})
		return append(checks, skipped(checkTargets))
	}
	defer func() { _ = cli.Close() }()

	checks = append(checks, Check{
		Name:   checkDaemon,
		Status: StatusPass,
		Detail: fmt.Sprintf(detailDaemonOK, cli.APIVersion()),
	})

	targets, err := cli.Targets(ctx, Filter{})
	if err != nil {
		return append(checks, Check{
			Name:   checkTargets,
			Status: StatusFail,
			Detail: err.Error(),
			Fix:    fixRetry,
		})
	}

	return append(checks, targetsCheck(targets), dnsTierCheck(ctx, cli))
}

// dnsTierCheck reports whether khaos can stand its chaos resolver up at all,
// and how many it already has.
//
// The linkage half is checked here rather than discovered during a run, because
// the failure is otherwise invisible until the worst moment: `khaos run dns.*`
// imports an image, creates a container, starts it, and the container dies
// looking for `/lib64/ld-linux-x86-64.so.2`. The operator sees an exec error
// about a path they never typed. One line in `doctor` turns that into the build
// flag that fixes it.
func dnsTierCheck(ctx context.Context, cli *Client) Check {
	// Counted first, because it changes what a dynamic build's refusal MEANS.
	// A failure to list is not a failure of the tier: khaos can still stand a
	// resolver up, it just cannot say what is already there, and reporting that
	// as a broken tier would send an operator to rebuild a binary that is fine.
	running := -1
	if resolvers, err := cli.Resolvers(ctx); err == nil {
		running = len(resolvers)
	}

	if err := SelfStatic(); err != nil {
		return Check{
			Name:   checkDNSTier,
			Status: StatusFail,
			Detail: fmt.Sprintf(detailDNSDynamic, max(running, 0)),
			Fix:    fixDNSDynamic,
		}
	}

	if running < 0 {
		return Check{
			Name:   checkDNSTier,
			Status: StatusPass,
			Detail: detailDNSStatic,
		}
	}

	return Check{
		Name:   checkDNSTier,
		Status: StatusPass,
		Detail: fmt.Sprintf(detailResolvers, detailDNSStatic, running),
	}
}

func skipped(name string) Check {
	return Check{Name: name, Status: StatusSkipped, Detail: detailSkipDaemon}
}

func socketCheck(path string, connectErr error) Check {
	if connectErr != nil && isSocketProblem(connectErr) {
		return Check{
			Name:   checkSocket,
			Status: StatusFail,
			Detail: connectErr.Error(),
			Fix:    socketFix(connectErr, path),
		}
	}
	return Check{
		Name:   checkSocket,
		Status: StatusPass,
		Detail: fmt.Sprintf(detailSocketOK, path),
	}
}

func targetsCheck(targets []Target) Check {
	consenting := 0
	for _, t := range targets {
		if t.Consented() {
			consenting++
		}
	}

	if consenting == 0 {
		return Check{
			Name:   checkTargets,
			Status: StatusFail,
			Detail: detailNone,
			Fix:    FixNoTargets,
		}
	}

	return Check{
		Name:   checkTargets,
		Status: StatusPass,
		Detail: fmt.Sprintf(
			detailTargets,
			consenting,
			LabelConsent,
			ConsentValue,
		),
	}
}

func isSocketProblem(err error) bool {
	return errors.Is(err, ErrSocketMissing) ||
		errors.Is(err, ErrSocketDenied) ||
		errors.Is(err, ErrNotASocket) ||
		errors.Is(err, ErrNothingListening)
}

func endpointFailureDetail(err error) string {
	if errors.Is(err, ErrNoEndpoint) {
		return detailNoEndpoint
	}
	return err.Error()
}

func endpointFix(err error) string {
	if errors.Is(err, ErrContextUnresolvable) {
		return fixContext
	}
	return fixNoEndpoint
}

func socketFix(err error, path string) string {
	if isPermissionDenied(err) {
		return permissionFix(path)
	}
	return fixDaemonLocal
}

func daemonFix(err error, endpoint Endpoint) string {
	if isPermissionDenied(err) {
		path, _ := endpoint.SocketPath()
		if path == "" {
			path = DockerSocketPath
		}
		return permissionFix(path)
	}

	if _, isSocket := endpoint.SocketPath(); !isSocket {
		return fmt.Sprintf(fixDaemonRemote, endpoint.Host)
	}

	return fixDaemonLocal
}

func isPermissionDenied(err error) bool {
	return errors.Is(err, ErrSocketDenied) || errors.Is(err, fs.ErrPermission)
}

func permissionFix(path string) string {
	name := fallbackUser
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return fmt.Sprintf(permissionFixFormat, name, path)
}

func contextSuffix(e Endpoint) string {
	if e.Name == "" {
		return ""
	}
	return fmt.Sprintf(" %q", e.Name)
}
