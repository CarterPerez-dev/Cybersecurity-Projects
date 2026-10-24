// ©AngelaMos | 2026
// experiment.go

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/authz"
	"github.com/CarterPerez-dev/khaos/internal/bindguard"
	"github.com/CarterPerez-dev/khaos/internal/dbx"
	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/idp"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lease"
	"github.com/CarterPerez-dev/khaos/internal/pki"
	"github.com/CarterPerez-dev/khaos/internal/rangelab"
	"github.com/CarterPerez-dev/khaos/internal/render"
	"github.com/CarterPerez-dev/khaos/internal/run"
	"github.com/CarterPerez-dev/khaos/internal/theme"
	"github.com/CarterPerez-dev/khaos/internal/workspace"
	"github.com/spf13/cobra"
)

const (
	flagBaselineFor = "baseline-for"
	flagFaultFor    = "fault-for"
	flagRecoverFor  = "recover-for"
	flagSampleEvery = "sample-every"
	flagFailOn      = "fail-on"
	flagRecord      = "record"
	flagOutput      = "output"
	flagJUnit       = "junit"
	flagMetricsOut  = "metrics-out"
	flagAbortAfter  = "abort-after"

	outputText = "text"
	outputJSON = "json"

	recordUsage = "a `dir`ectory to write the canonical run record into, as run.json plus an `events.jsonl` beside it carrying one line per observation. The record is what every other output khaos produces is a projection of, and it is the only form that survives the terminal scrolling away"

	outputUsage = "`text` for the terminal report, or `json` to write the run record to stdout and suppress every other line, so `khaos run x --output json | jq .verdict` works"

	junitUsage = "a `file` to write JUnit XML to, for CI test reporters. A run khaos declined to conclude from becomes a skipped rather than a failure, which is what stops thin evidence breaking a build on noise; only a control that failed in the direction this experiment declares a defect becomes a failure"

	metricsUsage = "a `file` to write Prometheus text exposition to, for node_exporter's textfile collector. Written atomically and consumed by pointing that collector at the directory; khaos stands up no server and opens no port"

	failOnUsage = "which outcomes keep a non-zero exit code. `any` is the default and narrows nothing, because a run khaos declined to conclude from exiting 0 is a green build on no evidence; `never` reports every measurable outcome as 0 and leaves the detail to the run record; or name the outcomes to gate on, comma separated, where `defect` alone is the shape a pipeline that should only break on a security regression wants. A rollback failure, a usage error and an internal error ignore this flag, because an unreverted fault makes every later job on that runner untrustworthy"

	catalogShort = "list the experiments khaos ships"
	catalogLong  = `Each experiment pairs a fault with two probes: one carrying a credential the
target should accept, and one carrying a credential it should refuse. The
second is the negative control, and it is what makes the verdict mean
anything.

Each experiment also declares its polarity, which is the direction that counts
as a defect for the control it is testing. Failing open is catastrophic for an
authentication check and a defensible trade for a rate-limit counter, so khaos
never assumes.`

	planShort = "show exactly what an experiment would do, without doing any of it"
	planLong  = `plan resolves the target, checks it against every refusal predicate, and prints
the hypothesis, the fault, the probes and the timing. It touches nothing.`

	runShort = "run an experiment and report whether the target failed closed or failed open"
	runLong  = `run establishes a steady state, injects the fault, measures the target with both
probes, reverts, and confirms recovery.

It reports two independent verdicts. The epistemic one says whether the run can
be believed at all. The directional one says which way the target broke. A
single verdict cannot tell a target that failed closed from one that was never
enforcing in the first place.`

	baselineUsage = "how long to measure the steady state before injecting"
	faultUsage    = "how long to hold the fault and measure under it"
	recoverUsage  = "how long to measure recovery after reverting"
	sampleUsage   = "how often each probe fires"

	headerExperiment = "EXPERIMENT"
	headerFamily     = "FAMILY"
	headerFault      = "FAULT"

	colExperiment = 32
	colFamily     = 12
	colFault      = 30

	labelHypothesis = "hypothesis"
	labelFault      = "fault"
	labelTarget     = "target"
	labelValid      = "valid probe"
	labelInvalid    = "invalid probe"
	labelPolarity   = "defect is"
	labelTiming     = "timing"
	labelVerdict    = "verdict"
	labelCause      = "cause"
	labelEvidence   = "evidence"
	labelWarning    = "warning"
	labelRun        = "run"
	labelWhy        = "why"
	labelWidth      = 14

	fieldLayout               = "%s%s%s\n"
	timingFormat              = "baseline %s, fault %s, recover %s, sampling every %s"
	verdictFormat             = "%s / %s"
	evidenceFormat            = "baseline %d paired samples, fault %d, recovery %d"
	stageFormat               = "%-9s %s"
	planOnly                  = "plan only, nothing was injected"
	msgUsingRange             = "using the running range: %s"
	errHalfSpecified          = "you gave %s but not %s; khaos will not fill one half from its range and the other from you, because that pauses a container you named and measures a service you did not"
	errNoExperiment           = "name the experiment to %s (known experiments: %s)"
	errNoRangeFor             = "%w by passing %s"
	errInconclusive           = "%w (%s)"
	errUnknownOutcome         = "%w: %q (khaos gates on: %s, or `any`, or `never`)"
	verdictThinEvidence       = "the sample cannot rule out a bypass"
	verdictRecoveryUnobserved = "recovery was never observed"
	errNoProxiedPath          = "%w: this experiment injects through khaos's fault proxy, and the running range has no %s; bring the range down and up again to create it"
	errNoVerifierPath         = "%w: this experiment arms khaos's own identity provider, and the running range has no %s; bring the range down and up again to create it"
	errIdPBind                = "khaos could not bind its identity provider on %s, which is where the range's verifier gateway is already looking for it: %w. Something else took that port since the range came up; bring the range down and up again to pick a new one"
	errIssuerPort             = "%w: khaos's identity provider must bind the port its issuer names, and %q does not name a usable one (%v); pass --issuer as a URL with an explicit port, such as http://host.docker.internal:45000"
	msgIdPUp                  = "khaos's identity provider is listening on %s, issuing as %s"

	errAuthorityBind = "khaos could not bind its certificate authority on %s, which is where the range's TLS gateway is already looking for it: %w. Something else took that port since the range came up; bring the range down and up again to pick a new one"
	msgAuthorityUp   = "khaos's certificate authority is serving the dependency on %s and revocation on %s, minting for %s"

	msgResolverUp = "khaos's chaos resolver %s is answering on %s, authoritative for %s, with %s as the control no fault touches"

	errNoResolverOn   = "no khaos chaos resolver is serving %s. The DNS family needs one, and the target has to have been CREATED pointing at it: `--dns` is fixed at container creation and Docker offers no way to change it afterwards. Run `khaos resolver up --network %[1]s` and recreate the target against the address it prints, or `khaos range up` for a stack that is already wired: %w"
	errResolverSilent = "khaos's chaos resolver %s did not answer its control surface at %s: %w"

	credTierFormat = "credential tier open on %s at %s over %s, which reports %q, acting on the role %s"

	errNoAdminSecret = "%s does not carry %s in its environment, so khaos has no administrative credential for the %s and will not guess one. khaos reads it from the container rather than taking it on a flag, because a flag is world-readable in /proc and a journal entry would outlive the run. Point --%s at the variable that holds it, or run `khaos range up --with-db` for a stack that is already wired"

	errNoPooledPath = "%w: this experiment rotates the credential a service's own connection pool authenticated with, and the running range has no %s; bring the range down and up again with `khaos range up --with-db`"

	errAuthzBind = "khaos could not bind the authorization dependency it plays on %s, which is where the target's own authorization check is already looking: %w. Something else took that port since the range came up; bring the range down and up again to pick a new one"

	msgAuthzUp = "khaos is answering authorization decisions on %s, allowing every credential until it is told otherwise"

	// Every parameter can also arrive in the environment, which is the only
	// channel that does not put a credential in the world-readable process
	// table. Same convention as the resolver nonce.
	paramEnv = "%s [or %s]"

	envParamPrefix = "KHAOS_"
	flagWordSep    = "-"
	envWordSep     = "_"

	errNoSubjectSecret = "%s does not carry %s in its environment, so khaos cannot read the credential its own connection pool authenticated with, and a rotation it cannot undo is not one khaos will perform"

	errTargetOffNetwork = "%s is not attached to %s, so it cannot be using the chaos resolver that serves it and khaos could not count its queries: %w"
	errProxyBind        = "khaos could not bind its fault proxy on %s, which is where the range's proxied gateway is already looking for it: %w. Something else took that port since the range came up; bring the range down and up again to pick a new one"
	msgProxyUp          = "khaos's fault proxy is listening on %s, forwarding to %s"

	groupExperiments = "experiments"
	titleExperiments = "Experiments:"

	paramDefault = "%s (defaults to %q)"
	flagPrefix   = "--"
	pairFormat   = "%s %s"
	listSep      = ", "
)

var ErrDefectFound = errors.New(
	"the target broke in the direction this experiment declares a defect",
)

var ErrNotRecovered = errors.New(
	"the target did not return to its steady state after khaos reverted the fault, so it may still be degraded",
)

var ErrUnusableIssuer = errors.New(
	"that issuer does not tell khaos where to listen",
)

var ErrInconclusive = errors.New(
	"this run did not reach a conclusion, so nothing can be concluded from it either way",
)

var ErrDeviated = errors.New(
	"the target broke in a direction this experiment does not declare a defect, which is the correct outcome with an availability cost khaos did not measure",
)

func newCatalogCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "catalog",
		Short: catalogShort,
		Long:  catalogLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCatalog(cmd.OutOrStdout())
		},
	}
}

// Every experiment is its own subcommand, so an operator sees exactly the flags
// it declares; the console regenerates the tree without being told the line.
func newPlanCmd() *cobra.Command {
	cmd := experimentParent("plan <experiment>", planShort, planLong)

	for _, definition := range experiment.Catalog() {
		cmd.AddCommand(newPlanExperimentCmd(definition))
	}

	return cmd
}

func newRunCmd() *cobra.Command {
	cmd := experimentParent("run <experiment>", runShort, runLong)

	for _, definition := range experiment.Catalog() {
		cmd.AddCommand(newRunExperimentCmd(definition))
	}

	return cmd
}

// experimentParent resolves a name and nothing else. Unknown flags are tolerated
// so `khaos run typo --url x` reports the unknown experiment, not the flag.
func experimentParent(use, short, long string) *cobra.Command {
	verb := strings.Fields(use)[0]

	cmd := &cobra.Command{
		Use:                use,
		Short:              short,
		Long:               long,
		Args:               cobra.ArbitraryArgs,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(_ *cobra.Command, args []string) error {
			return unknownExperiment(verb, args)
		},
	}

	cmd.AddGroup(&cobra.Group{ID: groupExperiments, Title: titleExperiments})

	return cmd
}

func unknownExperiment(verb string, args []string) error {
	if len(args) > 0 {
		if _, err := experiment.Lookup(args[0]); err != nil {
			return err
		}
	}
	return fmt.Errorf(
		errNoExperiment,
		verb,
		strings.Join(experiment.Names(), listSep),
	)
}

func newPlanExperimentCmd(definition experiment.Definition) *cobra.Command {
	cmd := &cobra.Command{
		Use:     definition.Name,
		Short:   definition.Summary,
		Long:    planLong,
		GroupID: groupExperiments,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			given, err := experimentInputs(cmd, definition)
			if err != nil {
				return err
			}
			return runPlan(cmd.Context(), cmd.OutOrStdout(), definition, given)
		},
	}

	experimentFlags(cmd, definition)

	return cmd
}

func newRunExperimentCmd(definition experiment.Definition) *cobra.Command {
	cmd := &cobra.Command{
		Use:     definition.Name,
		Short:   definition.Summary,
		Long:    runLong,
		GroupID: groupExperiments,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			given, err := experimentInputs(cmd, definition)
			if err != nil {
				return err
			}
			ttl, err := cmd.Flags().GetDuration(flagTTL)
			if err != nil {
				return err
			}

			// Parsed BEFORE the run, so a typo that would have silenced the
			// defect code is refused instead of discovered afterwards.
			raw, err := cmd.Flags().GetString(flagFailOn)
			if err != nil {
				return err
			}

			gate, err := ParseGate(raw)
			if err != nil {
				return err
			}

			shape, err := outputShape(cmd)
			if err != nil {
				return err
			}

			into, err := cmd.Flags().GetString(flagRecord)
			if err != nil {
				return err
			}

			projections, err := projectionsOf(cmd)
			if err != nil {
				return err
			}

			return runExperiment(
				cmd.Context(),
				cmd.OutOrStdout(),
				definition,
				ttl,
				given,
				gate,
				Output{
					Shape:       shape,
					Record:      into,
					Projections: projections,
					Diagnostic:  cmd.ErrOrStderr(),
				},
			)
		},
	}

	experimentFlags(cmd, definition)
	cmd.Flags().Duration(flagTTL, lease.DefaultTTL, ttlUsage)
	cmd.Flags().String(flagFailOn, FailOnAny, failOnUsage)
	cmd.Flags().String(flagRecord, "", recordUsage)
	cmd.Flags().String(flagOutput, outputText, outputUsage)
	cmd.Flags().String(flagJUnit, "", junitUsage)
	cmd.Flags().String(flagMetricsOut, "", metricsUsage)

	return cmd
}

func experimentFlags(cmd *cobra.Command, definition experiment.Definition) {
	cmd.Flags().String(flagProject, "", projectUsage)

	// Registered empty even where a default is declared: Bind applies defaults.
	for _, param := range definition.Params {
		cmd.Flags().String(param.Name, "", paramUsage(param))
	}

	cmd.Flags().
		Duration(flagBaselineFor, experiment.DefaultBaselineFor, baselineUsage)
	cmd.Flags().Duration(flagFaultFor, experiment.DefaultFaultFor, faultUsage)
	cmd.Flags().
		Duration(flagRecoverFor, experiment.DefaultRecoveryFor, recoverUsage)
	cmd.Flags().
		Duration(flagSampleEvery, experiment.DefaultSampleInterval, sampleUsage)
	cmd.Flags().Int(flagAbortAfter, 0,
		"stop and revert after this many consecutive unhealthy probe pairs; zero disables the rule")
}

// paramUsage names the environment variable too, because a channel an operator
// cannot discover is a channel nobody uses -- and for a credential it is the
// only one that keeps the value out of the world-readable process table.
func paramUsage(param experiment.Param) string {
	usage := param.Usage
	if param.Default != "" {
		usage = fmt.Sprintf(paramDefault, usage, param.Default)
	}

	return fmt.Sprintf(paramEnv, usage, envFor(param.Name))
}

type inputs struct {
	Project    string
	Supplied   map[string]string
	Timing     experiment.Timing
	AbortAfter int
	Expected   experiment.Identity
}

func experimentInputs(
	cmd *cobra.Command,
	definition experiment.Definition,
) (inputs, error) {
	project, err := cmd.Flags().GetString(flagProject)
	if err != nil {
		return inputs{}, err
	}

	// Changed, not a non-empty value: `--invalid-token ""` means no Authorization
	// header at all, which an operator has to be able to ask for.
	supplied := map[string]string{}
	for _, param := range definition.Params {
		if !cmd.Flags().Changed(param.Name) {
			// A FLAG is not the only way in, and for a credential it is the
			// worst one: /proc/<pid>/cmdline is world-readable (mode 444,
			// measured) while /proc/<pid>/environ is 400, which is why the
			// chaos resolver's nonce has always been an environment variable
			// rather than an argument. An experiment can require two live
			// credentials, so argv-only put both of an operator's secrets in
			// the process table and in shell history.
			if value, given := os.LookupEnv(envFor(param.Name)); given {
				supplied[param.Name] = value
			}

			continue
		}

		value, err := cmd.Flags().GetString(param.Name)
		if err != nil {
			return inputs{}, err
		}

		supplied[param.Name] = value
	}

	timing, err := experimentTiming(cmd)
	if err != nil {
		return inputs{}, err
	}

	abortAfter, err := cmd.Flags().GetInt(flagAbortAfter)
	if err != nil || abortAfter < 0 {
		return inputs{}, errors.New(
			"--abort-after must be zero or a positive count",
		)
	}
	return inputs{
		Project:    project,
		Supplied:   supplied,
		Timing:     timing,
		AbortAfter: abortAfter,
	}, nil
}

// envFor is the environment variable that supplies a parameter when its flag is
// absent. Derived from the parameter's own name rather than listed, so a new
// parameter gets the channel without anyone remembering to add it:
// `--revocable-token` reads `KHAOS_REVOCABLE_TOKEN`.
//
// Precedence is flag, then environment, then the range, then the declaration's
// default. The environment beats the range because both are the operator
// speaking and the range is only a convenience.
func envFor(param string) string {
	return envParamPrefix + strings.ToUpper(
		strings.ReplaceAll(param, flagWordSep, envWordSep),
	)
}

func experimentTiming(cmd *cobra.Command) (experiment.Timing, error) {
	durations := map[string]time.Duration{}

	for _, name := range []string{flagBaselineFor, flagFaultFor, flagRecoverFor, flagSampleEvery} {
		value, err := cmd.Flags().GetDuration(name)
		if err != nil {
			return experiment.Timing{}, err
		}
		durations[name] = value
	}

	return experiment.Timing{
		BaselineFor:    durations[flagBaselineFor],
		FaultFor:       durations[flagFaultFor],
		RecoveryFor:    durations[flagRecoverFor],
		SampleInterval: durations[flagSampleEvery],
	}, nil
}

func runCatalog(out io.Writer) error {
	fmt.Fprintln(out)
	fmt.Fprintf(out, rowLayout, render.Indent,
		theme.Fg(theme.TextFaint, render.Cell(headerExperiment, colExperiment)),
		theme.Fg(theme.TextFaint, render.Cell(headerFamily, colFamily)),
		theme.Fg(theme.TextFaint, render.Cell(headerFault, colFault)),
		theme.Fg(theme.TextFaint, "DEFECT IS"))

	for _, definition := range experiment.Catalog() {
		fmt.Fprintf(
			out,
			rowLayout,
			render.Indent,
			theme.Fg(
				theme.TextBright,
				render.Cell(definition.Name, colExperiment),
			),
			theme.Fg(
				theme.TextNormal,
				render.Cell(definition.Family, colFamily),
			),
			theme.Fg(
				theme.TextDim,
				render.Cell(definition.FaultKind, colFault),
			),
			theme.Fg(
				directionColor(definition.Polarity.Defects[0]),
				definition.Polarity.Declared(),
			),
		)

		fmt.Fprintf(
			out,
			noteLayout,
			render.FixIndent,
			theme.Fg(theme.TextDim, definition.Summary),
		)
	}

	fmt.Fprintln(out)
	return nil
}

func runPlan(
	ctx context.Context,
	out io.Writer,
	definition experiment.Definition,
	given inputs,
) error {
	work, err := workspace.OpenShared(ctx)
	if err != nil {
		return err
	}
	defer work.Close()

	supplied, err := fillFromRange(
		ctx,
		out,
		work.Docker,
		definition,
		given.Supplied,
	)
	if err != nil {
		return err
	}

	spec, err := experiment.Build(definition.Name, supplied, given.Timing)
	if err != nil {
		return err
	}

	project := given.Project
	guard := dockerx.Guard{Project: project, SelfID: dockerx.SelfContainerID()}

	target, err := work.Docker.Accept(
		ctx,
		spec.Fault.Target,
		dockerx.Filter{Project: project},
		guard,
	)
	if err != nil {
		return err
	}

	if err := verifyReplayTarget(
		given.Expected, target, work.Docker,
	); err != nil {
		return err
	}
	describe(out, spec, target.Name)
	note(out, planOnly)
	fmt.Fprintln(out)

	return nil
}

func describe(out io.Writer, spec experiment.Experiment, resolved string) {
	fmt.Fprintln(out)
	field(out, labelHypothesis, spec.Hypothesis.String())
	field(out, labelFault, spec.Fault.Kind)
	field(out, labelTarget, resolved)
	field(out, labelValid, spec.Probes.Valid.Describe())
	field(out, labelInvalid, spec.Probes.Invalid.Describe())
	field(
		out,
		labelPolarity,
		spec.Polarity.Declared()+" ("+spec.Polarity.Rationale+")",
	)

	timing := spec.Timing
	field(out, labelTiming, fmt.Sprintf(timingFormat,
		orDefault(timing.BaselineFor, experiment.DefaultBaselineFor),
		orDefault(timing.FaultFor, experiment.DefaultFaultFor),
		orDefault(timing.RecoveryFor, experiment.DefaultRecoveryFor),
		orDefault(timing.SampleInterval, experiment.DefaultSampleInterval)))
	fmt.Fprintln(out)
}

// prepared is everything a run needs resolved before anything is injected:
// the workspace lock, the experiment with its parameters bound, and the
// container whose consent khaos checked.
type prepared struct {
	work     *workspace.Workspace
	spec     experiment.Experiment
	accepted dockerx.Target
	guard    dockerx.Guard
	project  string
}

// prepareRun does every step that can still refuse. Separated from the run
// itself because nothing here touches the target: if this returns an error,
// khaos has injected nothing and has nothing to revert.
//
// The caller owns closing the workspace, because the lock has to outlive
// this function and be released after the run rather than before it.
func prepareRun(
	ctx context.Context,
	human io.Writer,
	definition experiment.Definition,
	given inputs,
) (prepared, error) {
	work, err := workspace.OpenExclusive(ctx)
	if err != nil {
		return prepared{}, err
	}

	out := prepared{work: work, project: given.Project}
	if err := work.RequireClean(); err != nil {
		return out, err
	}
	out.guard = dockerx.Guard{
		Project: out.project,
		SelfID:  dockerx.SelfContainerID(),
	}

	supplied, err := fillFromRange(
		ctx,
		human,
		work.Docker,
		definition,
		given.Supplied,
	)
	if err != nil {
		return out, err
	}

	out.spec, err = experiment.Build(
		definition.Name,
		supplied,
		given.Timing,
	)
	if err != nil {
		return out, err
	}

	out.accepted, err = work.Docker.Accept(
		ctx,
		out.spec.Fault.Target,
		dockerx.Filter{Project: out.project},
		out.guard,
	)
	if err == nil {
		err = verifyReplayTarget(given.Expected, out.accepted, work.Docker)
	}
	out.spec.AbortAfter = given.AbortAfter
	attachConfiguration(&out.spec, given, out.accepted, work.Docker)

	return out, err
}

// Output is where a run's results go. Grouped because they are one decision
// -- what this invocation should emit -- rather than three.
type Output struct {
	Shape       string
	Record      string
	Projections Projections

	// Diagnostic is where a failure that is NOT the verdict goes: separate
	// from stdout so --output json stays one decodable document, and
	// separate from the report because json discards the report while this
	// still has to be seen.
	Diagnostic io.Writer
}

// human is where the terminal report goes, and under --output json that is
// nowhere: stdout has to carry the record and nothing else, or piping it
// into jq fails on the first banner line.
func (o Output) human(out io.Writer) io.Writer {
	if o.Shape == outputJSON {
		return io.Discard
	}

	return out
}

// diagnostic defaults to stderr rather than to the report stream, so a caller
// that forgets to set it cannot silently reintroduce the contamination.
func (o Output) diagnostic() io.Writer {
	if o.Diagnostic == nil {
		return os.Stderr
	}

	return o.Diagnostic
}

func runExperiment(
	ctx context.Context,
	out io.Writer,
	definition experiment.Definition,
	ttl time.Duration,
	given inputs,
	gate Gate,
	emit Output,
) (failure error) {
	human := emit.human(out)

	ready, err := prepareRun(ctx, human, definition, given)
	if ready.work != nil {
		defer ready.work.Close()
	}

	if err != nil {
		return err
	}

	work := ready.work
	spec, accepted := ready.spec, ready.accepted
	project, guard := ready.project, ready.guard
	session := run.NewSession(work.Env(), work.Journal, ttl)
	closeTiers := func() {}
	defer func() { closeTiers() }()
	defer finishSession(ctx, session, &failure)

	env, closeTiers, err := standUpTiers(
		ctx,
		human,
		work,
		&spec,
		accepted,
		dockerx.Filter{Project: project},
		guard,
		session,
	)
	if err != nil {
		return err
	}

	session.Configure(env)
	guard.ExpectedID = accepted.ID

	engine := wire(
		human,
		session,
		work.Docker,
		dockerx.Filter{Project: project},
		guard,
	)

	describe(human, spec, accepted.Name)

	result, runErr := underLease(ctx, engine, spec, session)

	result.RunID = session.RunID()
	if env.Cred != nil {
		result.Configuration.Versions["database"] = env.Cred.Version()
	}
	if emit.Record == "" {
		emit.Record = work.Paths.Run(result.RunID)
	}
	cleanup, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), run.CleanupTimeout,
	)
	cleanupErr := session.RevertAll(cleanup, nil)
	cancel()
	if cleanupErr != nil {
		result.Observation.RollbackFailed = true
		result.Verdict.Warnings = append(
			result.Verdict.Warnings, experiment.WarningRollbackFailed,
		)
		result.Verdict.Reasons = append(
			result.Verdict.Reasons, cleanupErr.Error(),
		)
		runErr = errors.Join(runErr, cleanupErr)
	}

	// The exit is decided BEFORE anything is reported, because the record
	// carries the code: the exit status is the only part of a run most CI
	// ever sees, and a record that cannot explain it is not a record of the
	// run.
	outcome := gated(gate, exitFor(result, runErr))

	reportVerdict(human, result)

	return emitRecord(out, definition, result, outcome, emit)
}

func finishSession(
	ctx context.Context,
	session *run.Session,
	failure *error,
) {
	cleanup, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), run.CleanupTimeout,
	)
	defer cancel()
	cleanupErr := session.RevertAll(cleanup, nil)
	if caught := recover(); caught != nil {
		if cleanupErr != nil {
			panic(fmt.Errorf("%v; emergency cleanup: %w", caught, cleanupErr))
		}
		panic(caught)
	}
	*failure = errors.Join(*failure, cleanupErr)
}

func wire(
	out io.Writer,
	session *run.Session,
	resolver run.Resolver,
	filter dockerx.Filter,
	guard dockerx.Guard,
) experiment.Engine {
	injector := &run.Injector{
		Session:  session,
		Resolver: resolver,
		Filter:   filter,
		Guard:    guard,
		Progress: func(record journal.Record, failure error) {
			if failure != nil {
				event(
					out,
					markError,
					theme.StatusError,
					fmt.Sprintf(
						faultFormat,
						record.Kind,
						record.TargetName,
						failure,
					),
				)

				return
			}

			event(
				out,
				markRevert,
				theme.StatusOK,
				subject(record.Kind, record.TargetName),
			)
		},
	}

	return experiment.Engine{
		Injector: injector,
		Report: func(e experiment.Event) {
			event(
				out,
				markPlan,
				theme.TextFaint,
				fmt.Sprintf(stageFormat, e.Stage, e.Detail),
			)
		},
	}
}

// underLease keeps the lease renewed while the run holds a fault, or `khaos
// reap` reverts it mid-measurement. A lapsed lease is an epistemic failure.
func underLease(
	ctx context.Context,
	engine experiment.Engine,
	spec experiment.Experiment,
	session *run.Session,
) (experiment.Result, error) {
	keepCtx, stopKeeping := context.WithCancel(ctx)
	renewals := make(chan error, 1)
	defer stopKeeping()

	go func() {
		renewals <- session.Lease().Keep(
			keepCtx,
			func(time.Time) error { return session.Renew() },
		)
	}()
	defer func() {
		stopKeeping()
		<-renewals
	}()

	result, runErr := engine.Run(ctx, spec)

	stopKeeping()

	keepErr := <-renewals
	renewals <- keepErr
	if keepErr != nil && !errors.Is(keepErr, context.Canceled) {
		result.Verdict.Epistemic = experiment.Aborted
		result.Verdict.Conclusive = false
		result.Verdict.Reasons = append(result.Verdict.Reasons, keepErr.Error())
		runErr = errors.Join(runErr, keepErr)
	}

	return result, runErr
}

// exitFor maps a finished run onto khaos's exit contract, and the ORDER is the
// contract: the state of the operator's system outranks the verdict about it.
func exitFor(result experiment.Result, runErr error) error {
	// The state khaos left the target in outranks every verdict about it, and
	// no --fail-on value may suppress either.
	if result.Observation.RollbackFailed {
		return &Exit{
			Code:    CodeRollback,
			Outcome: outcomeRollback,
			Err:     run.ErrRevertFailed,
		}
	}

	if result.Verdict.Recovery == experiment.Degraded {
		return &Exit{
			Code:    CodeRollback,
			Outcome: outcomeRollback,
			Err:     ErrNotRecovered,
		}
	}

	if runErr != nil {
		return runErr
	}

	// The DEFECT outranks the epistemic axis, because a proven bypass is
	// reported even on thin evidence: one leaked request is a proof.
	if result.Verdict.Defect {
		return &Exit{
			Code:    CodeDefect,
			Outcome: OutcomeDefect,
			Err:     ErrDefectFound,
		}
	}

	if code, outcome, matched := epistemicExit(
		result.Verdict.Epistemic,
	); matched {
		return &Exit{
			Code:    code,
			Outcome: outcome,
			Err: fmt.Errorf(
				errInconclusive,
				ErrInconclusive,
				result.Verdict.Epistemic,
			),
		}
	}

	// Deviated in a direction this experiment's polarity does NOT call a
	// defect: correct, with an availability cost khaos did not measure.
	if result.Verdict.Epistemic == experiment.Deviated {
		return &Exit{
			Code:    CodeDeviated,
			Outcome: OutcomeDeviated,
			Err:     ErrDeviated,
		}
	}

	// A HELD verdict khaos declined to call conclusive. Exiting 0 here would
	// assert a control held on evidence khaos itself refused to stand behind.
	if !result.Verdict.Conclusive {
		return &Exit{
			Code:    CodeInconclusive,
			Outcome: OutcomeInconclusive,
			Err: fmt.Errorf(
				errInconclusive,
				ErrInconclusive,
				verdictThinEvidence,
			),
		}
	}

	if result.Verdict.Recovery == experiment.Unobserved {
		return &Exit{
			Code:    CodeInconclusive,
			Outcome: OutcomeInconclusive,
			Err: fmt.Errorf(
				errInconclusive,
				ErrInconclusive,
				verdictRecoveryUnobserved,
			),
		}
	}

	return nil
}

func reportVerdict(out io.Writer, result experiment.Result) {
	fmt.Fprintln(out)

	field(out, labelVerdict, theme.Fg(
		directionColor(result.Verdict.Direction),
		fmt.Sprintf(
			verdictFormat,
			result.Verdict.Epistemic,
			result.Verdict.Direction,
		),
	))

	if result.Verdict.Cause != experiment.Undiagnosed {
		field(
			out,
			labelCause,
			theme.Fg(theme.StatePermitted, string(result.Verdict.Cause)),
		)
	}

	if result.RunID != "" {
		field(out, labelRun, result.RunID)
	}

	for _, warning := range result.Verdict.Warnings {
		field(out, labelWarning, theme.Fg(theme.StatusWarn, string(warning)))
	}

	field(out, labelEvidence, fmt.Sprintf(evidenceFormat,
		result.Observation.Baseline.Len(),
		result.Observation.Fault.Len(),
		result.Observation.Recovery.Len()))

	for _, reason := range result.Verdict.Reasons {
		field(out, labelWhy, reason)
	}

	fmt.Fprintln(out)
}

func field(out io.Writer, label, value string) {
	fmt.Fprintf(out, fieldLayout, render.Indent,
		theme.Fg(theme.TextFaint, render.Pad(label, labelWidth)), value)
}

func directionColor(direction experiment.Direction) theme.Color {
	switch direction {
	case experiment.Held:
		return theme.StateHeld
	case experiment.Denied:
		return theme.StateDenied
	case experiment.Permitted, experiment.Crashed:
		return theme.StatePermitted
	default:
		return theme.StateUndetermined
	}
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

func rangeSupplies() []string {
	return []string{
		experiment.ParamTarget,
		experiment.ParamURL,
		experiment.ParamToken,
		experiment.ParamRefusedFrom,
		experiment.ParamAuthority,
		experiment.ParamRevocable,
		experiment.ParamIssuer,
		experiment.ParamProxyListen,
		experiment.ParamProxyUpstream,
		experiment.ParamAuthorityListen,
		experiment.ParamAuthorityTLS,
		experiment.ParamAuthorityBase,
		experiment.ParamCertHost,
		experiment.ParamDNSHost,
		experiment.ParamResolverNetwork,
		experiment.ParamDNSAddress,
		experiment.ParamEngine,
		experiment.ParamEngineTarget,
		experiment.ParamSubjectRole,
		experiment.ParamSubjectVar,
		experiment.ParamHealthURL,
		experiment.ParamReadyURL,
		experiment.ParamSecretPath,
		experiment.ParamEnvVar,
		experiment.ParamAuthzListen,
	}
}

// tier is which of the range's gateways an experiment belongs to, derived from
// the injection registry. Each gateway isolates one tier's measurement path.
type tier int

const (
	tierDirect tier = iota
	tierProxy
	tierIdP
	tierTLS
	tierDNS
	tierCred
	tierPool
	tierSecret
	tierEnv
	tierAuthz

	// Three tiers over ONE gateway, because that gateway carries three
	// controls and each has its own measurement path. The mechanism cannot
	// tell them apart: all three sever with the same proxy.
	tierControlLimiter
	tierControlPolicy
	tierControlRules
)

func tierOf(definition experiment.Definition) tier {
	switch definition.Control {
	case experiment.SubjectLimiter:
		return tierControlLimiter
	case experiment.SubjectPolicy:
		return tierControlPolicy
	case experiment.SubjectRules:
		return tierControlRules
	}

	return tierForKind(definition.FaultKind)
}

func tierForKind(kind string) tier {
	switch {
	case inject.NeedsProxy(kind):
		return tierProxy
	case inject.NeedsAuthz(kind):
		return tierAuthz
	case inject.NeedsIdP(kind):
		return tierIdP
	case inject.NeedsPKI(kind):
		return tierTLS
	case inject.NeedsResolver(kind):
		return tierDNS
	case inject.NeedsEnv(kind):
		return tierEnv
	case inject.NeedsSecret(kind):
		return tierSecret
	case inject.IsPoolFault(kind):
		return tierPool
	case inject.NeedsCred(kind):
		return tierCred
	default:
		return tierDirect
	}
}

type rangeAnswers struct {
	Token     string
	Revocable string
	Authority string

	ProxyListen   string
	ProxyUpstream string

	// AuthorityBase is NOT derived from AuthorityListen: khaos binds a numeric
	// bridge address, while the container addresses `host.docker.internal`.
	AuthorityListen string
	AuthorityTLS    string
	AuthorityBase   string

	CertHost string

	// Where khaos binds the authorization dependency it plays. Same shape as
	// AuthorityListen and for the same reason: the fixture's own call is
	// already addressed at a fixed port on the bridge gateway.
	AuthzListen string
}

// tierAnswers is what one tier's own gateway and fixtures answer. Split out of
// rangeDefaults so a seventh tier adds a case rather than another ten lines to
// one function.
type tierAnswers struct {
	url          string
	target       string
	engine       string
	engineTarget string
	subjectRole  string
	subjectVar   string
	healthURL    string
	readyURL     string
	secretPath   string
	variable     string

	// Where khaos fetches a fresh input the control must refuse, once per
	// probe. The control family's negative control is signed, so it cannot
	// carry an appended nonce and has to be re-issued instead.
	refusedFrom string
}

// controlPath is the endpoint whose answer one control decides. Three tiers
// share one gateway, so the path is the only thing that separates them.
func controlPath(at tier) string {
	switch at {
	case tierControlLimiter:
		return rangelab.LimitedPath
	case tierControlPolicy:
		return rangelab.GovernedPath
	default:
		return rangelab.FilteredPath
	}
}

func answersFor(lab rangelab.Lab, at tier) tierAnswers {
	answers := tierAnswers{
		url:    lab.ProtectedURL(),
		target: rangelab.IDPName,
	}

	switch at {
	case tierProxy:
		answers.url = lab.ProxiedProtectedURL()
		answers.target = rangelab.ProxiedGatewayName

	// The target is the gateway, not the provider: the fault lands on khaos's
	// own provider, so the gateway is the only container to ask consent for.
	case tierIdP:
		answers.url = lab.VerifierProtectedURL()
		answers.target = rangelab.VerifierGatewayName

	case tierTLS:
		answers.url = lab.TLSProtectedURL()
		answers.target = rangelab.TLSGatewayName

	case tierDNS:
		answers.url = lab.DNSProtectedURL()
		answers.target = rangelab.DNSGatewayName

	case tierCred:
		answers.url = ""
		answers.target = rangelab.PostgresName
		answers.engine = string(dbx.Postgres)

	// The pooled faults measure the SERVICE and perform the rotation at the
	// engine, so they name both containers. The role is the fixture's own,
	// never khaos's administrative one.
	case tierPool:
		answers.url = lab.DBProtectedURL()
		answers.target = rangelab.DBGatewayName
		answers.engine = string(dbx.Postgres)
		answers.engineTarget = rangelab.PostgresName
		answers.subjectRole = rangelab.AppRole
		answers.subjectVar = rangelab.EnvDBPassword
		answers.healthURL = lab.DBHealthURL()
		answers.readyURL = lab.DBReadyURL()

	// The one family that breaks a FILE rather than a credential, so the
	// target is the service holding it and the path is read off the fixture
	// rather than guessed.
	case tierSecret:
		answers.url = lab.SecretProtectedURL()
		answers.target = rangelab.SecretGatewayName
		answers.secretPath = rangelab.SecretPath

	// A SECOND fixture, whose secret is in its environment. It is not a mode
	// of the file one because these faults replace the container, and doing
	// that to the file fixture would take the volume's experiments with it.
	case tierEnv:
		answers.url = lab.EnvProtectedURL()
		answers.target = rangelab.EnvGatewayName
		answers.variable = rangelab.SecretVariable

	// The CALLER is the target. khaos replaces the dependency it asks, so the
	// fixture is the only container whose consent is needed, and the
	// dependency is not a container at all.
	case tierAuthz:
		answers.url = lab.AuthzProtectedURL()
		answers.target = rangelab.AuthzGatewayName

	// One gateway, three endpoints. The target is the gateway in all three:
	// the fault lands on khaos's proxy in front of a dependency, so the
	// gateway is the only container whose consent is needed.
	case tierControlLimiter, tierControlPolicy, tierControlRules:
		answers.url = lab.ControlGatewayURL() + controlPath(at)
		answers.target = rangelab.ControlGatewayName
		answers.refusedFrom = lab.RefusedInputURL()

	default:
		// The direct tier's URL and target are the values set above.
	}

	return answers
}

func rangeDefaults(
	lab rangelab.Lab,
	answers rangeAnswers,
	at tier,
) map[string]string {
	tiered := answersFor(lab, at)

	defaults := map[string]string{
		experiment.ParamTarget:    tiered.target,
		experiment.ParamToken:     answers.Token,
		experiment.ParamRevocable: answers.Revocable,
		experiment.ParamAuthority: answers.Authority,
		experiment.ParamIssuer:    lab.Issuer,

		experiment.ParamProxyListen:   answers.ProxyListen,
		experiment.ParamProxyUpstream: answers.ProxyUpstream,

		experiment.ParamAuthorityListen: answers.AuthorityListen,
		experiment.ParamAuthorityTLS:    answers.AuthorityTLS,
		experiment.ParamAuthorityBase:   answers.AuthorityBase,
		experiment.ParamCertHost:        answers.CertHost,
		experiment.ParamAuthzListen:     answers.AuthzListen,

		experiment.ParamDNSHost:         rangelab.DNSDependencyName,
		experiment.ParamResolverNetwork: rangelab.NetworkName,

		// The redirect faults point at the range's ROGUE provider, which
		// approves every credential; an unroutable address would only be
		// another outage.
		experiment.ParamDNSAddress: rangelab.RogueAddress,
	}

	// TIER-CONDITIONAL answers are left out rather than filled with an empty
	// string. The credential tier has no url because its probes are database
	// connections, and no other tier has an engine. An empty answer would read
	// as "the range claims to answer this and cannot", which is the shape that
	// sends an operator looking for a flag that does nothing.
	for name, value := range map[string]string{
		experiment.ParamURL:          tiered.url,
		experiment.ParamRefusedFrom:  tiered.refusedFrom,
		experiment.ParamEngine:       tiered.engine,
		experiment.ParamEngineTarget: tiered.engineTarget,
		experiment.ParamSubjectRole:  tiered.subjectRole,
		experiment.ParamSubjectVar:   tiered.subjectVar,
		experiment.ParamHealthURL:    tiered.healthURL,
		experiment.ParamReadyURL:     tiered.readyURL,
		experiment.ParamSecretPath:   tiered.secretPath,
		experiment.ParamEnvVar:       tiered.variable,
	} {
		if value != "" {
			defaults[name] = value
		}
	}

	return defaults
}

// fillFromRange fills every unsupplied parameter from a running range, all of
// them or none: half-filling fuses the operator's target with the range's URL.
func fillFromRange(
	ctx context.Context,
	out io.Writer,
	reader rangelab.PortReader,
	definition experiment.Definition,
	supplied map[string]string,
) (map[string]string, error) {
	given, missing := partitionFillable(definition, supplied)

	if len(missing) == 0 {
		return supplied, nil
	}

	if len(given) > 0 {
		return nil, fmt.Errorf(
			errHalfSpecified,
			flagList(given),
			flagList(missing),
		)
	}

	lab, err := rangelab.Discover(ctx, reader)
	if err != nil {
		if errors.Is(err, rangelab.ErrNoRange) {
			return nil, fmt.Errorf(errNoRangeFor, err, flagList(missing))
		}
		return nil, err
	}

	// Refuse before announcing, or the note names a URL resolved to port 0.
	at := tierOf(definition)

	if err := requireTier(lab, at); err != nil {
		return nil, err
	}

	answers, err := askTheRange(
		ctx,
		reader,
		lab,
		fillable(definition, supplied),
		at,
	)
	if err != nil {
		return nil, err
	}

	defaults := rangeDefaults(lab, answers, at)
	filled := maps.Clone(supplied)

	answered := fillable(definition, supplied)
	resolved := make([]string, 0, len(answered))

	// Credentials stay out of the note; everything else khaos chose is named.
	for _, name := range answered {
		if defaults[name] == "" {
			continue
		}

		filled[name] = defaults[name]
		if !credentialParam(name) {
			resolved = append(
				resolved,
				fmt.Sprintf(pairFormat, name, defaults[name]),
			)
		}
	}

	note(out, fmt.Sprintf(msgUsingRange, strings.Join(resolved, listSep)))

	return filled, nil
}

func requireTier(lab rangelab.Lab, at tier) error {
	switch at {
	case tierProxy:
		if lab.ProxiedPort == 0 {
			return fmt.Errorf(
				errNoProxiedPath,
				rangelab.ErrRangeIncomplete,
				rangelab.ProxiedGatewayName,
			)
		}

	case tierIdP:
		if lab.VerifierPort == 0 || lab.Issuer == "" {
			return fmt.Errorf(
				errNoVerifierPath,
				rangelab.ErrRangeIncomplete,
				rangelab.VerifierGatewayName,
			)
		}

	case tierCred:
		return lab.RequireStatefulTier()

	case tierPool:
		if err := lab.RequireStatefulTier(); err != nil {
			return err
		}

		if lab.DBGatewayPort == 0 {
			return fmt.Errorf(
				errNoPooledPath,
				rangelab.ErrRangeIncomplete,
				rangelab.DBGatewayName,
			)
		}

	case tierSecret:
		return lab.RequireSecretTier()

	case tierEnv:
		return lab.RequireEnvTier()

	case tierAuthz:
		return lab.RequireAuthzTier()

	// The limiter is the one control whose dependency is a real engine, so it
	// is the one that needs the opt-in stateful tier. The other two are
	// refused only when the gateway or its address is missing.
	case tierControlLimiter:
		if err := lab.RequireStatefulTier(); err != nil {
			return err
		}

		return lab.RequireControlTier(rangelab.ControlLimiter)

	case tierControlPolicy:
		return lab.RequireControlTier(rangelab.ControlPolicy)

	case tierControlRules:
		return lab.RequireControlTier(rangelab.ControlRules)

	default:
		// The direct tier needs only the gateway Discover already found.
	}

	return nil
}

func partitionFillable(
	definition experiment.Definition,
	supplied map[string]string,
) ([]string, []string) {
	answerable := rangeSupplies()
	given := []string{}
	missing := []string{}

	for _, param := range definition.Params {
		if !slices.Contains(answerable, param.Name) {
			continue
		}

		// Presence, not emptiness: `--token ""` was supplied. Whether an empty
		// value is allowed is Bind's refusal to make.
		if _, present := supplied[param.Name]; present {
			given = append(given, param.Name)
			continue
		}

		if param.Default != "" {
			continue
		}

		missing = append(missing, param.Name)
	}

	return given, missing
}

// fillable is what the range should ANSWER, a wider set than what is missing,
// because precedence is operator, then range, then declaration default.
func fillable(
	definition experiment.Definition,
	supplied map[string]string,
) []string {
	answerable := rangeSupplies()
	out := []string{}

	for _, param := range definition.Params {
		if !slices.Contains(answerable, param.Name) {
			continue
		}

		if _, present := supplied[param.Name]; present {
			continue
		}

		out = append(out, param.Name)
	}

	return out
}

func flagList(names []string) string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, flagPrefix+name)
	}
	return strings.Join(out, listSep)
}

// startProxy binds khaos's fault proxy where the target already looks for it:
// the gateway's environment is fixed at container creation, so khaos has no say.
func startProxy(
	_ context.Context,
	out io.Writer,
	_ rangelab.PortReader,
	spec experiment.Experiment,
) (*proxy.Proxy, error) {
	listen, upstream := spec.ProxyListen, spec.ProxyUpstream

	fault, err := proxy.Open(listen, upstream, spec.ProxyProbe)
	if err != nil {
		if errors.Is(err, proxy.ErrUnsafeBind) {
			return nil, err
		}
		return nil, fmt.Errorf(errProxyBind, listen, err)
	}

	note(out, fmt.Sprintf(msgProxyUp, fault.Addr(), fault.Upstream()))

	return fault, nil
}

// startProvider binds khaos's own identity provider on the Docker bridge gateway
// at the port the issuer names, never a wildcard: the target addresses the issuer
// as `host.docker.internal`, which does not resolve here.
// providerListen is where the provider will bind, computed before the bind so
// the guard and the listener are given the same string.
func providerListen(
	ctx context.Context,
	reader rangelab.PortReader,
	spec experiment.Experiment,
) (string, error) {
	port, err := portOf(spec.IdP.Issuer())
	if err != nil {
		return "", err
	}

	gateway, err := reader.BridgeGateway(ctx)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(gateway, strconv.Itoa(port)), nil
}

func startProvider(
	ctx context.Context,
	out io.Writer,
	reader rangelab.PortReader,
	spec experiment.Experiment,
) error {
	issuer := spec.IdP.Issuer()

	listen, err := providerListen(ctx, reader, spec)
	if err != nil {
		return err
	}

	if err := spec.IdP.Listen(listen); err != nil {
		return fmt.Errorf(errIdPBind, listen, err)
	}

	note(out, fmt.Sprintf(msgIdPUp, listen, issuer))

	return nil
}

// standUpTiers starts whichever in-process tiers this experiment needs. Every
// one must answer before the BASELINE is measured through it, or the difference
// between the phases is khaos rather than the fault.
// standUpTiers opens whichever authorities this experiment declares. Each tier
// has the same shape — stand it up, hand back the closer — so a sixth tier adds
// one branch rather than another paragraph of lifecycle.
func standUpTiers(
	ctx context.Context,
	out io.Writer,
	work *workspace.Workspace,
	spec *experiment.Experiment,
	target dockerx.Target,
	filter dockerx.Filter,
	guard dockerx.Guard,
	session *run.Session,
) (inject.Env, func(), error) {
	env := work.Env()

	var closers []func()

	closeAll := func() {
		for _, close := range closers {
			close()
		}
	}

	tiers := []func() (func(), error){
		func() (func(), error) {
			return standUpProxyTier(ctx, out, work.Docker, spec, target, &env)
		},
		func() (func(), error) {
			return standUpIdPTier(ctx, out, work.Docker, spec, &env)
		},
		func() (func(), error) {
			return standUpPKITier(ctx, out, work.Docker, spec, &env)
		},
		func() (func(), error) {
			return standUpAuthzTier(ctx, out, work.Docker, spec, &env)
		},
		func() (func(), error) {
			return standUpDNSTier(ctx, out, work.Docker, spec, target, &env)
		},
		func() (func(), error) {
			return standUpSecretTier(ctx, spec, target, &env)
		},
		func() (func(), error) {
			env.EnvPlan = spec.Env

			return nil, nil
		},
		func() (func(), error) {
			return standUpCredTier(
				ctx,
				out,
				work.Docker,
				spec,
				target,
				credSources{filter: filter, guard: guard},
				&env,
				session,
			)
		},
	}

	for _, stand := range tiers {
		closer, err := stand()
		if err != nil {
			return env, closeAll, err
		}
		if closer != nil {
			closers = append(closers, closer)
		}
	}

	return env, closeAll, nil
}

// managedBind is the NARROW half of the bind guard and it lives here because
// the allowed set comes from the daemon. Each binding package carries the
// structural half -- no wildcard, no privileged port, loopback or a bridge --
// and a kernel bridge is not enough: measured on a development host, that
// includes a CNI pod bridge, a swarm gateway bridge, forty-nine user-defined
// bridges carrying other projects' containers, and on a host whose LAN
// interface is enslaved to a bridge, the routable LAN address itself.
func managedBind(
	ctx context.Context,
	docker *dockerx.Client,
	addr, subject string,
) error {
	gateways, err := docker.Gateways(ctx)
	if err != nil {
		return err
	}

	return bindguard.Managed(addr, subject, gateways)
}

func standUpProxyTier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	target dockerx.Target,
	env *inject.Env,
) (func(), error) {
	if spec.ProxyFault == nil {
		return nil, nil
	}

	if err := managedBind(
		ctx,
		docker,
		spec.ProxyListen,
		proxy.SubjectProxy,
	); err != nil {
		return nil, err
	}

	fault, err := startProxy(ctx, out, docker, *spec)
	if err != nil {
		return nil, err
	}

	if err := wireProxyArrival(ctx, docker, fault, spec, target); err != nil {
		return nil, errors.Join(err, fault.Close())
	}

	env.Proxy = fault
	env.ProxyFault = *spec.ProxyFault

	return func() { _ = fault.Close() }, nil
}

func wireProxyArrival(
	ctx context.Context,
	docker *dockerx.Client,
	fault *proxy.Proxy,
	spec *experiment.Experiment,
	target dockerx.Target,
) error {
	endpoints, err := docker.Endpoints(ctx, target.ID)
	if err != nil {
		return err
	}
	var addresses []string
	for _, endpoint := range endpoints {
		if endpoint == nil {
			continue
		}
		if endpoint.IPAddress.IsValid() {
			addresses = append(addresses, endpoint.IPAddress.String())
		}
		if endpoint.GlobalIPv6Address.IsValid() {
			addresses = append(addresses, endpoint.GlobalIPv6Address.String())
		}
	}
	if err := fault.WatchSources(addresses); err != nil {
		return err
	}
	spec.Consulted = fault.TargetConnections
	spec.ConsultedWhat = "the dependency through khaos's proxy"
	spec.Delivered = fault.FaultConnections
	spec.DeliveredWhat = "connect to the fault proxy from the target's network addresses"
	spec.DeliveredHint = "Check the target's dependency route and any address translation between the target and the proxy."
	return nil
}

func standUpIdPTier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	env *inject.Env,
) (func(), error) {
	if spec.IdPTrap == nil {
		return nil, nil
	}

	listen, err := providerListen(ctx, docker, *spec)
	if err != nil {
		return nil, err
	}

	if err := managedBind(
		ctx,
		docker,
		listen,
		idp.SubjectProvider,
	); err != nil {
		return nil, err
	}

	if err := startProvider(ctx, out, docker, *spec); err != nil {
		return nil, err
	}

	env.IdP = spec.IdP
	env.IdPTrap = *spec.IdPTrap

	return func() { _ = spec.IdP.Close() }, nil
}

func standUpPKITier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	env *inject.Env,
) (func(), error) {
	if spec.PKITrap == nil {
		return nil, nil
	}

	for addr, subject := range map[string]string{
		spec.AuthorityListen: pki.SubjectRevocation,
		spec.AuthorityTLS:    pki.SubjectDependency,
	} {
		if err := managedBind(ctx, docker, addr, subject); err != nil {
			return nil, err
		}
	}

	if err := startAuthority(out, *spec); err != nil {
		return nil, err
	}

	env.Authority = spec.Authority
	env.PKITrap = *spec.PKITrap

	return func() { _ = spec.Authority.Close() }, nil
}

// standUpAuthzTier binds khaos's authorization dependency BEFORE the baseline,
// which is not optional: the target's authorization call has to be answered
// through the whole run, or the baseline measures a dependency that is down and
// the fault window is the only one where it is up.
func standUpAuthzTier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	env *inject.Env,
) (func(), error) {
	if spec.AuthzTrap == nil {
		return nil, nil
	}

	if err := managedBind(
		ctx,
		docker,
		spec.AuthzListen,
		authz.SubjectAuthz,
	); err != nil {
		return nil, err
	}

	if err := spec.Authz.Listen(spec.AuthzListen); err != nil {
		// The guard refuses BEFORE the bind is attempted, so the port-collision
		// advice below is wrong for the one refusal an operator will actually
		// hit: an address khaos will not serve this from.
		if errors.Is(err, bindguard.ErrUnsafeBind) {
			return nil, err
		}

		return nil, fmt.Errorf(errAuthzBind, spec.AuthzListen, err)
	}

	note(out, fmt.Sprintf(msgAuthzUp, spec.Authz.Addr()))

	env.Authz = spec.Authz
	env.AuthzTrap = *spec.AuthzTrap

	return func() { _ = spec.Authz.Close() }, nil
}

// standUpDNSTier ATTACHES rather than starts: `--dns` is fixed at container
// creation, so a resolver started now would be one nothing is pointed at.
func standUpDNSTier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	target dockerx.Target,
	env *inject.Env,
) (func(), error) {
	if spec.DNSTrap == nil {
		return nil, nil
	}

	client, err := attachResolver(ctx, out, docker, *spec)
	if err != nil {
		return nil, err
	}

	if err := wireArrivalGuard(ctx, docker, spec, client, target); err != nil {
		return nil, err
	}

	env.Resolver = client
	env.ResolverNetwork = spec.ResolverNetwork
	env.DNSTrap = *spec.DNSTrap

	// This resolver outlives the khaos process; armed, it would stay armed.
	return func() {
		_, _ = client.Disarm(context.WithoutCancel(ctx))
	}, nil
}

// standUpSecretTier resolves the mount the secret arrives on, which is the one
// thing khaos replicates into its helper container, and mints the nonce that
// authorises the helper's own subcommand. No closer: the helper exits on its
// own and the revert runs another one.
func standUpSecretTier(
	_ context.Context,
	spec *experiment.Experiment,
	target dockerx.Target,
	env *inject.Env,
) (func(), error) {
	if spec.Secret == nil {
		return nil, nil
	}

	mount, err := dockerx.MountFor(target, spec.Secret.Mutation.Path)
	if err != nil {
		return nil, err
	}

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	spec.Secret.Mount = mount
	spec.Secret.Nonce = nonce
	env.SecretPlan = spec.Secret

	return nil, nil
}

// standUpCredTier opens the tier and hands back the closer that removes the
// role khaos minted, so a minted role cannot outlive the run even when the
// revert already restored the credential.
// credSources carries what resolving a SECOND container needs, because the
// pooled faults measure one container and perform the rotation at another, and
// both have to pass the refusal predicates.
type credSources struct {
	filter dockerx.Filter
	guard  dockerx.Guard
}

func standUpCredTier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	target dockerx.Target,
	sources credSources,
	env *inject.Env,
	session *run.Session,
) (func(), error) {
	if spec.Cred == nil {
		return nil, nil
	}

	plan, err := openCredTier(
		ctx, out, docker, *spec, target, sources, env, session,
	)
	if err != nil {
		return nil, err
	}

	env.Cred = spec.Cred.Tier
	env.CredTrap = spec.Cred.Tier.Trap()
	env.CredPlan = plan

	return nil, nil
}

// openCredTier reads the administrative credential out of the TARGET's own
// environment and dials the engine on the container's own address. Neither the
// credential nor a published port is involved: the first would outlive the run
// in a journal or a command line, and the second would need the operator to
// publish a database to the host.
// credContainers resolves the engine, which is a SECOND container for a pooled
// fault, and reads the environment of both. The engine goes through the same
// refusal predicates as the target: khaos mutates state on it, so its consent
// is not implied by the target's.
func credContainers(
	ctx context.Context,
	docker *dockerx.Client,
	cred *experiment.CredSpec,
	target dockerx.Target,
	sources credSources,
) (dockerx.Target, map[string]string, map[string]string, error) {
	engine := target

	if cred.EngineTarget != "" {
		accepted, err := docker.Accept(
			ctx,
			cred.EngineTarget,
			sources.filter,
			dockerx.Guard{
				Project: sources.guard.Project,
				SelfID:  sources.guard.SelfID,
			},
		)
		if err != nil {
			return engine, nil, nil, err
		}

		engine = accepted
	}

	engineEnv, err := docker.ContainerEnv(ctx, engine.ID)
	if err != nil {
		return engine, nil, nil, err
	}

	if engine.ID == target.ID {
		return engine, engineEnv, engineEnv, nil
	}

	targetEnv, err := docker.ContainerEnv(ctx, target.ID)
	if err != nil {
		return engine, nil, nil, err
	}

	return engine, engineEnv, targetEnv, nil
}

// credRecipe is what a cold-started khaos needs to undo the fault, and it
// carries no credential: each one is named by the variable it is READ FROM, on
// the container that holds it.
func credRecipe(
	cred *experiment.CredSpec,
	config dbx.Config,
	engine, target dockerx.Target,
	environ map[string]string,
) (inject.CredPlan, dbx.Credential, error) {
	plan := inject.CredPlan{
		Engine:   cred.Engine,
		Address:  config.Address,
		Database: cred.Database,
		Admin: inject.CredSource{
			ContainerID: engine.ID,
			Role:        cred.Admin,
			PasswordVar: cred.AdminVar,
		},
	}

	if cred.Subject == "" {
		return plan, dbx.Credential{}, nil
	}

	value, ok := environ[cred.SubjectVar]
	if !ok || value == "" {
		return inject.CredPlan{}, dbx.Credential{}, fmt.Errorf(
			errNoSubjectSecret,
			target.Name,
			cred.SubjectVar,
		)
	}

	plan.Subject = &inject.CredSource{
		ContainerID: target.ID,
		Role:        cred.Subject,
		PasswordVar: cred.SubjectVar,
	}

	return plan, dbx.Credential{Role: cred.Subject, Password: value}, nil
}

func openCredTier(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec experiment.Experiment,
	target dockerx.Target,
	sources credSources,
	env *inject.Env,
	session *run.Session,
) (inject.CredPlan, error) {
	cred := spec.Cred

	engine, engineEnv, environ, err := credContainers(
		ctx,
		docker,
		cred,
		target,
		sources,
	)
	if err != nil {
		return inject.CredPlan{}, err
	}

	password, found := engineEnv[cred.AdminVar]
	if !found || password == "" {
		return inject.CredPlan{}, fmt.Errorf(
			errNoAdminSecret,
			engine.Name,
			cred.AdminVar,
			cred.Engine,
			experiment.ParamAdminVar,
		)
	}

	network, address, err := docker.OwnAddress(ctx, engine.ID)
	if err != nil {
		return inject.CredPlan{}, err
	}

	config := dbx.Config{
		Engine:   cred.Engine,
		Address:  net.JoinHostPort(address, cred.Port),
		Database: cred.Database,
		Admin:    dbx.Credential{Role: cred.Admin, Password: password},
	}

	plan, _, err := credRecipe(cred, config, engine, target, environ)
	if err != nil {
		return inject.CredPlan{}, err
	}

	env.Cred = cred.Tier
	env.CredTrap = cred.Tier.Trap()
	env.CredPlan = plan
	session.Configure(*env)
	if err := session.Renew(); err != nil {
		return inject.CredPlan{}, err
	}
	if err := session.Inject(
		ctx, inject.KindCredentialTier, engine,
	); err != nil {
		return inject.CredPlan{}, err
	}

	event(
		out,
		markPlan,
		theme.TextFaint,
		fmt.Sprintf(
			credTierFormat,
			cred.Engine,
			config.Address,
			network,
			cred.Tier.Version(),
			cred.Tier.Role(),
		),
	)

	return plan, nil
}

// wireArrivalGuard counts the TARGET's own queries for the name under fault,
// which separates a control that failed closed from a fault that never arrived.
func wireArrivalGuard(
	ctx context.Context,
	docker *dockerx.Client,
	spec *experiment.Experiment,
	client *dnsrv.Client,
	target dockerx.Target,
) error {
	address, err := docker.NetworkAddress(ctx, target.ID, spec.ResolverNetwork)
	if err != nil {
		return fmt.Errorf(
			errTargetOffNetwork,
			target.Name,
			spec.ResolverNetwork,
			err,
		)
	}

	host := spec.DNSHost

	spec.Consulted = func() (int64, error) {
		return client.Queries(context.WithoutCancel(ctx), address, host)
	}

	return nil
}

func requireDNSTier(lab rangelab.Lab, want func(string) bool) error {
	if !want(experiment.ParamDNSHost) &&
		!want(experiment.ParamResolverNetwork) {
		return nil
	}

	return lab.RequireDNSTier()
}

func attachResolver(
	ctx context.Context,
	out io.Writer,
	docker *dockerx.Client,
	spec experiment.Experiment,
) (*dnsrv.Client, error) {
	resolver, err := docker.FindResolver(ctx, spec.ResolverNetwork)
	if err != nil {
		return nil, fmt.Errorf(errNoResolverOn, spec.ResolverNetwork, err)
	}

	control := dockerx.ResolverControlURL(resolver.Address)

	client := dnsrv.NewClient(resolver.Address, control, resolver.Nonce, "")

	health, err := client.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf(errResolverSilent, resolver.Name, control, err)
	}

	client.ControlName = health.Control

	state, err := client.State(ctx)
	if err != nil {
		return nil, fmt.Errorf(errResolverSilent, resolver.Name, control, err)
	}

	client.Zone = state.Zone

	if _, err := client.Disarm(ctx); err != nil {
		return nil, err
	}

	note(out, fmt.Sprintf(
		msgResolverUp,
		resolver.Name,
		resolver.Address,
		spec.DNSHost,
		health.Control,
	))

	return client, nil
}

// startAuthority binds BOTH of the certificate authority's listeners. Neither
// address is discovered; the TLS gateway is already dialling specific ones.
func startAuthority(
	out io.Writer,
	spec experiment.Experiment,
) (failure error) {
	defer func() {
		if failure != nil {
			failure = errors.Join(failure, spec.Authority.Close())
		}
	}()
	if err := spec.Authority.Listen(spec.AuthorityListen); err != nil {
		return fmt.Errorf(errAuthorityBind, spec.AuthorityListen, err)
	}

	if err := spec.Authority.ListenTLS(spec.AuthorityTLS); err != nil {
		return fmt.Errorf(errAuthorityBind, spec.AuthorityTLS, err)
	}

	// An HONEST chain up front, or the baseline builds one per connection and the
	// leaf's serial changes under the target while khaos is revoking it.
	if err := spec.Authority.Disarm(); err != nil {
		return err
	}

	note(out, fmt.Sprintf(
		msgAuthorityUp,
		spec.AuthorityTLS,
		spec.AuthorityListen,
		spec.Authority.Host(),
	))

	return nil
}

func portOf(issuer string) (int, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return 0, fmt.Errorf(errIssuerPort, ErrUnusableIssuer, issuer, err)
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port <= 0 {
		return 0, fmt.Errorf(errIssuerPort, ErrUnusableIssuer, issuer, err)
	}

	return port, nil
}

func credentialParam(name string) bool {
	return name == experiment.ParamToken ||
		name == experiment.ParamRevocable
}

// askForCredentials mints whichever credentials this experiment declared, from
// the one fixture that will be asked to verify them.
func askForCredentials(
	ctx context.Context,
	lab rangelab.Lab,
	want func(string) bool,
	at tier,
	answers *rangeAnswers,
) error {
	issue, err := issuerFor(lab, at)
	if err != nil {
		return err
	}

	if want(experiment.ParamToken) {
		token, err := issue(ctx)
		if err != nil {
			return err
		}

		answers.Token = token
	}

	// A SECOND credential: revoking the one khaos keeps presenting as valid
	// would also take away the stream proving the target is serving at all.
	// It comes from the same issuer, because a fixture that authenticates
	// locally refuses anything it did not hand out and khaos would be
	// measuring that refusal instead of the fault.
	if want(experiment.ParamRevocable) {
		revocable, err := issue(ctx)
		if err != nil {
			return err
		}

		answers.Revocable = revocable
	}

	return nil
}

// proxyEndpointFor resolves which dependency this run's proxy sits in front
// of. Every control family member severs with the same mechanism, so the
// address comes from the tier rather than from the fault.
func proxyEndpointFor(
	ctx context.Context,
	reader rangelab.PortReader,
	lab rangelab.Lab,
	at tier,
) (string, string, error) {
	switch at {
	case tierControlLimiter:
		return lab.ControlEndpoint(ctx, reader, rangelab.ControlLimiter)
	case tierControlPolicy:
		return lab.ControlEndpoint(ctx, reader, rangelab.ControlPolicy)
	case tierControlRules:
		return lab.ControlEndpoint(ctx, reader, rangelab.ControlRules)
	default:
		return lab.ProxyEndpoint(ctx, reader)
	}
}

// issuerFor is whichever fixture will be the one VERIFYING. For the secret
// family that is the fixture itself, because khaos never reads the secret and a
// token signed with any other key would be refused for a reason that has
// nothing to do with the fault.
func issuerFor(
	lab rangelab.Lab,
	at tier,
) (func(context.Context) (string, error), error) {
	switch at {
	case tierSecret:
		if err := lab.RequireSecretTier(); err != nil {
			return nil, err
		}

		return lab.IssueSecretToken, nil

	case tierEnv:
		if err := lab.RequireEnvTier(); err != nil {
			return nil, err
		}

		return lab.IssueEnvToken, nil

	case tierAuthz:
		if err := lab.RequireAuthzTier(); err != nil {
			return nil, err
		}

		return lab.IssueAuthzToken, nil

	case tierControlLimiter, tierControlPolicy, tierControlRules:
		return lab.IssueControlToken, nil

	default:
		// Every other tier's credential comes from the range's own identity
		// provider through the direct gateway.
		return lab.IssueToken, nil
	}
}

func askTheRange(
	ctx context.Context,
	reader rangelab.PortReader,
	lab rangelab.Lab,
	missing []string,
	at tier,
) (rangeAnswers, error) {
	answers := rangeAnswers{}
	want := func(name string) bool { return slices.Contains(missing, name) }

	if err := askForCredentials(ctx, lab, want, at, &answers); err != nil {
		return rangeAnswers{}, err
	}

	if want(experiment.ParamProxyListen) ||
		want(experiment.ParamProxyUpstream) {
		listen, upstream, err := proxyEndpointFor(ctx, reader, lab, at)
		if err != nil {
			return rangeAnswers{}, err
		}
		answers.ProxyListen = listen
		answers.ProxyUpstream = upstream
	}

	if err := requireDNSTier(lab, want); err != nil {
		return rangeAnswers{}, err
	}

	if want(experiment.ParamAuthority) {
		authority, err := lab.AuthorityURL(ctx, reader)
		if err != nil {
			return rangeAnswers{}, err
		}
		answers.Authority = authority
	}

	if want(experiment.ParamAuthzListen) {
		listen, err := lab.AuthzListenAddr(ctx, reader)
		if err != nil {
			return rangeAnswers{}, err
		}
		answers.AuthzListen = listen
	}

	if want(experiment.ParamAuthorityListen) ||
		want(experiment.ParamAuthorityTLS) ||
		want(experiment.ParamAuthorityBase) ||
		want(experiment.ParamCertHost) {
		wiring, err := lab.AuthorityEndpoint(ctx, reader)
		if err != nil {
			return rangeAnswers{}, err
		}

		answers.AuthorityListen = wiring.Listen
		answers.AuthorityTLS = wiring.TLS
		answers.AuthorityBase = wiring.Base
		answers.CertHost = wiring.Host
	}

	return answers, nil
}
