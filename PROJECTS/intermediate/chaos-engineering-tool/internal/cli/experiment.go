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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/CarterPerez-dev/khaos/internal/dnsrv"
	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/inject"
	"github.com/CarterPerez-dev/khaos/internal/inject/proxy"
	"github.com/CarterPerez-dev/khaos/internal/journal"
	"github.com/CarterPerez-dev/khaos/internal/lease"
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
	// Wide enough for the longest NAME in the catalogue, because the experiment
	// name is the thing an operator types. `identity.claim_foreign_issuer` was
	// truncated to `identity.claim_foreign_is...` at 30, which is a listing that
	// cannot be copied from.
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

// Every experiment is its own subcommand, so the flags an operator sees are
// exactly the parameters the selected experiment declares. Registering the union
// of every experiment's parameters on one `run` would show a beginner twenty
// flags that do nothing for the experiment they picked, and deciding the set
// from a positional argument is not available in the console surface at all:
// the console regenerates the command tree without being told the line.
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
// on purpose: without that, `khaos run typo --url x` reports the unknown FLAG,
// burying the only thing wrong with the line.
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
			return runExperiment(
				cmd.Context(),
				cmd.OutOrStdout(),
				definition,
				ttl,
				given,
			)
		},
	}

	experimentFlags(cmd, definition)
	cmd.Flags().Duration(flagTTL, lease.DefaultTTL, ttlUsage)

	return cmd
}

func experimentFlags(cmd *cobra.Command, definition experiment.Definition) {
	cmd.Flags().String(flagProject, "", projectUsage)

	// Every parameter registers with an empty default even when it declares one,
	// because an empty value is how khaos tells "the operator did not set this"
	// from "the operator set this". Defaults are applied once, by Bind.
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
}

func paramUsage(param experiment.Param) string {
	if param.Default == "" {
		return param.Usage
	}
	return fmt.Sprintf(paramDefault, param.Usage, param.Default)
}

type inputs struct {
	Project  string
	Supplied map[string]string
	Timing   experiment.Timing
}

func experimentInputs(
	cmd *cobra.Command,
	definition experiment.Definition,
) (inputs, error) {
	project, err := cmd.Flags().GetString(flagProject)
	if err != nil {
		return inputs{}, err
	}

	// Changed, not a non-empty value. Sniffing for "" cannot tell an operator who
	// typed `--invalid-token ""` from one who typed nothing, and those must differ:
	// an empty credential means no Authorization header at all, which is the
	// canonical unauthenticated negative control. Treating it as unset silently
	// replaced it with the default and made that control inexpressible.
	supplied := map[string]string{}
	for _, param := range definition.Params {
		if !cmd.Flags().Changed(param.Name) {
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

	return inputs{Project: project, Supplied: supplied, Timing: timing}, nil
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

func runExperiment(
	ctx context.Context,
	out io.Writer,
	definition experiment.Definition,
	ttl time.Duration,
	given inputs,
) error {
	work, err := workspace.OpenExclusive(ctx)
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

	// The target is resolved and checked against every refusal predicate BEFORE
	// anything is printed, exactly as plan does it. Without this, a target khaos
	// would refuse by name reached the engine instead, the baseline found nothing
	// serving, and the run reported `baseline-not-met` and exit 0 against a target
	// khaos never even accepted. That is the same "true statement about a run that
	// never had a chance, blaming the target" failure the parameter model exists
	// to kill, arriving on the output path instead of the input path.
	accepted, err := work.Docker.Accept(
		ctx,
		spec.Fault.Target,
		dockerx.Filter{Project: project},
		guard,
	)
	if err != nil {
		return err
	}

	env, closeTiers, err := standUpTiers(ctx, out, work, &spec, accepted)
	if err != nil {
		return err
	}

	defer closeTiers()

	session := run.NewSession(env, work.Journal, ttl)

	engine := wire(
		out,
		session,
		work.Docker,
		dockerx.Filter{Project: project},
		guard,
	)

	describe(out, spec, accepted.Name)

	result, runErr := underLease(ctx, engine, spec, session)

	result.RunID = session.RunID()
	reportVerdict(out, result)

	return exitFor(result, runErr)
}

// wire builds the injector and the engine. Everything in here is progress
// reporting and none of it is policy, which is why the two literals are long
// and why they belong together away from the run itself.
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

// underLease runs the experiment while the session's lease is kept alive, which
// it must be for as long as the run holds a fault. Without the renewal `khaos
// reap` reverts the fault partway through and the engine scores a target that
// was never under fault as a clean survival.
//
// A lease that STOPPED being renewed is therefore an epistemic failure, not a
// warning: the fault may have been reverted underneath the measurement, so the
// result cannot be believed even though the engine returned one.
func underLease(
	ctx context.Context,
	engine experiment.Engine,
	spec experiment.Experiment,
	session *run.Session,
) (experiment.Result, error) {
	keepCtx, stopKeeping := context.WithCancel(ctx)
	renewals := make(chan error, 1)

	go func() {
		renewals <- session.Lease().Keep(
			keepCtx,
			func(time.Time) error { return session.Renew() },
		)
	}()

	result, runErr := engine.Run(ctx, spec)

	stopKeeping()

	if keepErr := <-renewals; !errors.Is(keepErr, context.Canceled) {
		result.Verdict.Epistemic = experiment.Aborted
		result.Verdict.Conclusive = false
		result.Verdict.Reasons = append(result.Verdict.Reasons, keepErr.Error())
		runErr = errors.Join(runErr, keepErr)
	}

	return result, runErr
}

// exitFor maps a finished run onto khaos's exit contract, and the ORDER is the
// contract. The operator's first question is the state of their own system, not
// the verdict about it, so a failed rollback and a target khaos never saw come
// back both rank ABOVE the defect the run went looking for.
func exitFor(result experiment.Result, runErr error) error {
	if runErr != nil {
		return runErr
	}

	if result.Observation.RollbackFailed {
		return run.ErrRevertFailed
	}

	// A target khaos could not see come back is a target khaos may have left
	// broken, and that must not exit 0. It ranks above the defect check for the
	// same reason a failed rollback does: the operator's first job is the state
	// of their system, not the verdict about it.
	if result.Verdict.Recovery == experiment.Degraded {
		return ErrNotRecovered
	}

	if result.Verdict.Defect {
		return ErrDefectFound
	}

	// A run that measured nothing must not exit 0. Every inconclusive epistemic
	// outcome used to, so `khaos run network.dependency_partial --bytes 999999`
	// against a gateway explicitly configured to fail open was a GREEN build: the
	// fault was too large to confirm, the engine aborted before measuring, the
	// verdict text said so honestly, and the exit code said success. Design
	// section 8 assigns 4 to inconclusive, and that is what this produces.
	if !conclusive(result.Verdict.Epistemic) {
		return fmt.Errorf(
			errInconclusive,
			ErrInconclusive,
			result.Verdict.Epistemic,
		)
	}

	// khaos's OWN confidence field, which the exit code used to ignore entirely.
	// A HELD verdict carrying `Conclusive=false` says in its own reasons that the
	// sample cannot rule out a bypass, and then exited 0 anyway — the same
	// dishonesty the inconclusive exit code was introduced to end, arriving one
	// field over.
	if !result.Verdict.Conclusive {
		return fmt.Errorf(errInconclusive, ErrInconclusive, verdictThinEvidence)
	}

	// Recovery that was never observed is not recovery.
	if result.Verdict.Recovery == experiment.Unobserved {
		return fmt.Errorf(
			errInconclusive,
			ErrInconclusive,
			verdictRecoveryUnobserved,
		)
	}

	return nil
}

// conclusive reports whether the epistemic axis reached a belief about the target
// at all. Passed and Deviated are answers; everything else says the run could not
// produce one.
func conclusive(epistemic experiment.Epistemic) bool {
	return epistemic == experiment.Passed || epistemic == experiment.Deviated
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

	// The cause is only printed when something established one. An UNDIAGNOSED
	// line on every run would read as a field khaos failed to fill rather than a
	// diagnosis it never attempted.
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

// rangeSupplies names the parameters a running range answers for itself. It is
// the key set of rangeDefaults, pinned by a test, and it has to be knowable
// without touching anything because it decides whether khaos looks for a range
// at all.
func rangeSupplies() []string {
	return []string{
		experiment.ParamTarget,
		experiment.ParamURL,
		experiment.ParamToken,
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
	}
}

// tier is which of the range's three gateways an experiment belongs to, and it
// is derived from the registry rather than from the experiment's name. Each
// gateway exists so one injection tier is measured on an uncontaminated path:
// pointing a Docker-native experiment at a gateway that talks through a proxy
// measures the pair, and pointing a forgery experiment at a gateway whose issuer
// khaos cannot arm measures nothing at all.
type tier int

const (
	tierDirect tier = iota
	tierProxy
	tierIdP
	tierTLS
	tierDNS
)

func tierOf(kind string) tier {
	switch {
	case inject.NeedsProxy(kind):
		return tierProxy
	case inject.NeedsIdP(kind):
		return tierIdP
	case inject.NeedsPKI(kind):
		return tierTLS
	case inject.NeedsResolver(kind):
		return tierDNS
	default:
		return tierDirect
	}
}

// rangeDefaults answers per EXPERIMENT, not just per range. A proxy-tier
// experiment must probe the gateway whose own upstream runs through khaos's
// proxy; pointing it at the direct gateway would arm a fault on a path that
// gateway never uses and measure a service with no causal connection to it.
//
// The credential is always issued by the direct gateway. Both gateways share one
// identity provider, so the credential is valid at either, and issuing it on the
// direct path means token issuance never depends on the proxy already being up.
// rangeAnswers is everything khaos has to go and get before it can answer for
// the range. Keeping rangeDefaults pure over this is what lets a test pin the
// VALUES rather than only the key set.
type rangeAnswers struct {
	Token     string
	Revocable string
	Authority string

	// Where the range's proxied gateway expects khaos's proxy, and the
	// dependency behind it. Both come from the daemon rather than from what
	// `range up` chose, for the reason recorded on proxyPortOf.
	ProxyListen   string
	ProxyUpstream string

	// Where khaos binds its certificate authority's two listeners, and the URL
	// the TLS gateway reaches the revocation endpoints by.
	//
	// AuthorityBase is NOT derived from AuthorityListen. khaos binds the bridge
	// gateway's numeric address and the container addresses
	// `host.docker.internal`, so the two are different strings for the same
	// endpoint and conflating them is the identity provider's most expensive
	// bug.
	AuthorityListen string
	AuthorityTLS    string
	AuthorityBase   string

	// CertHost is the name the TLS gateway asks for, read back from its own
	// configuration for the same reason the issuer is: khaos has to mint for
	// the name the target expects, character for character.
	CertHost string
}

func rangeDefaults(
	lab rangelab.Lab,
	answers rangeAnswers,
	at tier,
) map[string]string {
	url := lab.ProtectedURL()
	target := rangelab.IDPName

	switch at {
	case tierProxy:
		url = lab.ProxiedProtectedURL()
	case tierIdP:
		// The target is the VERIFIER GATEWAY, not the provider container. That is
		// the one place this tier inverts the others: there the fault is applied
		// to the dependency and the gateway is probed, while here the fault is
		// applied to khaos's own in-process provider and the gateway is both the
		// subject and the thing khaos needs consent for. Naming the provider
		// container would ask consent for a container this experiment never
		// touches and leave the one it does measure unchecked.
		url = lab.VerifierProtectedURL()
		target = rangelab.VerifierGatewayName

	case tierTLS:
		// The TLS gateway, for the same reason the identity tier names the
		// verifier gateway: the fault is applied to khaos's own authority and
		// the gateway is both the subject and the thing khaos needs consent
		// for. Naming the dependency would ask consent for a container this
		// experiment never touches.
		url = lab.TLSProtectedURL()
		target = rangelab.TLSGatewayName

	case tierDNS:
		// The DNS gateway, and the target is the GATEWAY rather than the
		// dependency for the same reason again: the fault is applied to khaos's
		// resolver, and the gateway is both the subject and the container whose
		// consent khaos needs. The dependency is never touched at all here --
		// it stays healthy and reachable, and the target simply cannot find it.
		url = lab.DNSProtectedURL()
		target = rangelab.DNSGatewayName

	default:
		// The direct tier probes the protected URL and names the provider
		// container, both of which are already set above.
	}

	return map[string]string{
		experiment.ParamTarget:    target,
		experiment.ParamURL:       url,
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

		experiment.ParamDNSHost:         rangelab.DNSDependencyName,
		experiment.ParamResolverNetwork: rangelab.NetworkName,

		// The redirect faults point at the range's ROGUE provider rather than at
		// the documentation address they default to, and that is what makes them
		// findings instead of outages. The rogue approves every credential, so a
		// gateway that follows the redirect without verifying who it reached
		// serves the invalid control and khaos reports PERMITTED. Pointed at an
		// unroutable address the same fault only reproduces what three other
		// tiers already do to an unreachable dependency.
		experiment.ParamDNSAddress: rangelab.RogueAddress,
	}
}

// fillFromRange supplies everything the operator did not, from a running range.
// It is what makes the zero-flag commitment in the UX law real: khaos already
// knows the gateway's randomly chosen port and can ask it for a credential, so
// it does not make the operator repeat either one.
//
// Three states, not two, and the partition is derived from what the range can
// answer rather than from a hand-written pair of field checks. Filling part of
// an invocation fuses the operator's target with the range's URL, which pauses a
// container they named and measures a service they did not.
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

	// Refuse BEFORE announcing anything. Without this the note printed a URL
	// khaos had already resolved to port 0, immediately above the refusal saying
	// the part that would have supplied the port is missing.
	at := tierOf(definition.FaultKind)

	if at == tierProxy && lab.ProxiedPort == 0 {
		return nil, fmt.Errorf(
			errNoProxiedPath,
			rangelab.ErrRangeIncomplete,
			rangelab.ProxiedGatewayName,
		)
	}

	if at == tierIdP && (lab.VerifierPort == 0 || lab.Issuer == "") {
		return nil, fmt.Errorf(
			errNoVerifierPath,
			rangelab.ErrRangeIncomplete,
			rangelab.VerifierGatewayName,
		)
	}

	answers, err := askTheRange(
		ctx,
		reader,
		lab,
		fillable(definition, supplied),
	)
	if err != nil {
		return nil, err
	}

	defaults := rangeDefaults(lab, answers, at)
	filled := maps.Clone(supplied)

	// Filled from the wider set, so a range answer beats a generic declaration
	// default. See fillable.
	answered := fillable(definition, supplied)
	resolved := make([]string, 0, len(answered))

	// Credentials are deliberately omitted from the note. Everything else khaos
	// chose on the operator's behalf is named, because this line is the only thing
	// telling them which stack they are about to break.
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

// partitionFillable splits the parameters this experiment declares AND the range
// can answer into the ones the operator gave and the ones they did not.
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

		// Presence, not emptiness: an operator who typed `--token ""` DID supply
		// it, and refusing with "you gave --target, --url but not --token"
		// contradicts the line they just typed. An empty value that is not allowed
		// is Bind's refusal to make, by name.
		if _, present := supplied[param.Name]; present {
			given = append(given, param.Name)
			continue
		}

		// A parameter the declaration already answers is not missing. Demanding a
		// value the experiment supplies itself sends the operator looking for
		// something khaos already has.
		if param.Default != "" {
			continue
		}

		missing = append(missing, param.Name)
	}

	return given, missing
}

// fillable is what the range should ANSWER, which is a wider set than what is
// missing, and separating the two is a correctness fix rather than tidying.
//
// `missing` drives the half-specified refusal, so a parameter the declaration
// already defaults is deliberately not in it: demanding a value khaos supplies
// itself sends the operator looking for nothing. But a default is a GENERIC
// answer, and the range knows its own topology, so where both exist the range's
// answer has to win.
//
// `--dns-address` is the first parameter where that mattered and it mattered a
// lot. Its default is a documentation address with nothing on it, which makes a
// redirect fault indistinguishable from the dependency outage three other tiers
// already test. The range answers it with its rogue provider, which approves
// every credential, and that is what turns the fault into the finding research 05
// section 10 names: a hostname allowlist does not merely stop working when the
// name moves, it authorises the new host. With the default winning, the gate's
// own assertion caught it: the report named the documentation address.
//
// Precedence is operator, then range, then declaration.
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

// startProxy stands up khaos's in-process fault proxy where the target is already
// looking for it. The address is not khaos's choice: the proxied gateway's
// environment is fixed at container creation, so khaos binds the port that target
// is ALREADY addressing rather than one it would have picked.
//
// The listen address is the Docker bridge gateway, discovered rather than assumed.
// Measured: a container reaches a host listener there, a listener on the target
// network's own gateway is unreachable, and binding that one address leaves the
// proxy dead on loopback and dead on the host's LAN address.
func startProxy(
	_ context.Context,
	out io.Writer,
	_ rangelab.PortReader,
	spec experiment.Experiment,
) (*proxy.Proxy, error) {
	// From the SPEC, not from a range. These are declared parameters now, so a
	// fully specified invocation against somebody's own stack no longer fails
	// looking for a fixture it was never going to use.
	listen, upstream := spec.ProxyListen, spec.ProxyUpstream

	fault, err := proxy.Open(listen, upstream)
	if err != nil {
		// A refusal to bind THERE is not a port collision, and telling the
		// operator to bring the range down and up again prescribes a fix that
		// cannot work. Only a genuine collision gets the collision advice.
		if errors.Is(err, proxy.ErrUnsafeBind) {
			return nil, err
		}
		return nil, fmt.Errorf(errProxyBind, listen, err)
	}

	note(out, fmt.Sprintf(msgProxyUp, fault.Addr(), fault.Upstream()))

	return fault, nil
}

// startProvider binds khaos's own identity provider where the target is already
// addressing it. The address is not khaos's choice: the verifier gateway's
// environment is fixed at container creation, so khaos binds the port that
// container will dial rather than one it would have picked.
//
// The listen address is the Docker bridge gateway, discovered rather than
// assumed, which is the same measured fact the fault proxy rests on. A wildcard
// bind would put a deliberately-wrong identity provider on the operator's
// network, which is the one thing this tier must never do.
func startProvider(
	ctx context.Context,
	out io.Writer,
	reader rangelab.PortReader,
	spec experiment.Experiment,
) error {
	// The ISSUER already says where to bind, so this tier needs no range at all.
	//
	// It used to call rangelab.Discover unconditionally, which meant a fully
	// specified invocation against somebody's own stack failed looking for a
	// range it was never going to use — while khaos's own refusal text invited
	// exactly that: "or point khaos at your own stack instead". Seventeen of the
	// eighteen identity experiments were unusable outside the bundled fixture.
	//
	// khaos cannot BIND the issuer's host, because the target addresses it as
	// `host.docker.internal` and that name does not resolve here. It binds the
	// Docker bridge gateway on the issuer's PORT, which is the same address the
	// container reaches and the same discovery the fault proxy already does.
	issuer := spec.IdP.Issuer()

	port, err := portOf(issuer)
	if err != nil {
		return err
	}

	gateway, err := reader.BridgeGateway(ctx)
	if err != nil {
		return err
	}

	listen := net.JoinHostPort(gateway, strconv.Itoa(port))

	if err := spec.IdP.Listen(listen); err != nil {
		return fmt.Errorf(errIdPBind, listen, err)
	}

	note(out, fmt.Sprintf(msgIdPUp, listen, issuer))

	return nil
}

// standUpTiers starts whichever of khaos's own in-process tiers this experiment
// needs, and returns a closer for all of them.
//
// Every one of them has to be answering before the BASELINE, not before the
// fault, and that is the same reason three times over: the baseline is measured
// through them, so a proxy, a provider or an authority that arrived at
// injection time would make the two phases travel different paths and the
// difference between them would be KHAOS rather than the fault.
//
// The closer is returned rather than deferred here, because deferring inside
// this function would tear the tiers down before the run that measures through
// them has started.
func standUpTiers(
	ctx context.Context,
	out io.Writer,
	work *workspace.Workspace,
	spec *experiment.Experiment,
	target dockerx.Target,
) (inject.Env, func(), error) {
	env := work.Env()

	var closers []func()

	closeAll := func() {
		for _, close := range closers {
			close()
		}
	}

	if spec.ProxyFault != nil {
		fault, err := startProxy(ctx, out, work.Docker, *spec)
		if err != nil {
			return env, closeAll, err
		}

		closers = append(closers, func() { _ = fault.Close() })

		env.Proxy = fault
		env.ProxyFault = *spec.ProxyFault
	}

	// The experiment already BUILT the provider, because its probes mint out of
	// it and minting needs no listener. All that is left is to bind it where the
	// target is already looking.
	if spec.IdPTrap != nil {
		if err := startProvider(ctx, out, work.Docker, *spec); err != nil {
			return env, closeAll, err
		}

		closers = append(closers, func() { _ = spec.IdP.Close() })

		env.IdP = spec.IdP
		env.IdPTrap = *spec.IdPTrap
	}

	// The authority plays the dependency the target dials, so without it the
	// baseline measures a dependency that is simply absent.
	if spec.PKITrap != nil {
		if err := startAuthority(out, *spec); err != nil {
			return env, closeAll, err
		}

		closers = append(closers, func() { _ = spec.Authority.Close() })

		env.Authority = spec.Authority
		env.PKITrap = *spec.PKITrap
	}

	// The resolver is ATTACHED, not started, and that is the one structural
	// difference between this tier and the other three in-process ones.
	//
	// khaos cannot stand a resolver up at run time and have the target use it:
	// `--dns` is fixed at container creation and Docker offers no API to change
	// it on a running container, measured, so a resolver created now would be
	// one nothing is pointed at. The resolver has to pre-exist the target, and
	// khaos finds the one already serving the target's network.
	if spec.DNSTrap != nil {
		client, err := attachResolver(ctx, out, work.Docker, *spec)
		if err != nil {
			return env, closeAll, err
		}

		// The liveness guard is wired HERE and not by the builder, and the
		// reason is structural: it needs the resolver client, which does not
		// exist until the run finds one, and the target's container address,
		// which needs the daemon. The identity tier can set its own counter at
		// build time because it BUILDS its provider; this tier attaches to one.
		//
		// The address is what makes the count a proof of arrival rather than a
		// number that is always non-zero. khaos's own confirmation queries come
		// from the host; the target's are forwarded by its embedded resolver out
		// of its own network namespace, so counting by source separates them.
		if err := wireArrivalGuard(
			ctx,
			work.Docker,
			spec,
			client,
			target,
		); err != nil {
			return env, closeAll, err
		}

		// Disarmed on the way out, so the recovery window is measured through a
		// WORKING resolver. Unlike the in-process tiers this authority outlives
		// the khaos process, so leaving it armed would leave the target unable
		// to resolve its dependency after khaos exited.
		closers = append(closers, func() {
			_, _ = client.Disarm(context.WithoutCancel(ctx))
		})

		env.Resolver = client
		env.ResolverNetwork = spec.ResolverNetwork
		env.DNSTrap = *spec.DNSTrap
	}

	return env, closeAll, nil
}

// attachResolver finds the chaos resolver serving the target's network and
// returns a client for it, with the fault disarmed and the confirmation
// control read back out of the resolver itself.
//
// Everything here is read back rather than remembered, which is the discipline
// the identity provider's most expensive bug established. The address comes
// from the daemon, because Docker refuses a static one on a network whose
// subnet it chose. The nonce comes off the container's label. And the control
// name comes from the resolver's own health endpoint, because the resolver is
// the only authority on which name it will refuse to fault.
// wireArrivalGuard installs the count of the TARGET's own queries for the name
// under fault, which is the proof-of-arrival control research 05 section 12
// makes mandatory.
//
// Without it khaos cannot distinguish "the control failed closed" from "the
// fault never reached the target", and the second is the likely one: `--dns` is
// fixed at container creation and Docker offers no way to change it afterwards,
// so a target that was not CREATED pointing at khaos's resolver never sends it a
// single query and every verdict about it would be about nothing.
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

// requireDNSTier refuses a DNS experiment against a range with no DNS gateway,
// BY NAME, before anything is probed.
//
// A missing gateway otherwise surfaces as a published port of zero, so the run
// blames the target for not enforcing when khaos was pointing at nowhere.
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

	// The zone is read back too, so a redirect's observable can name the honest
	// address the fault replaced rather than restating the one it served.
	state, err := client.State(ctx)
	if err != nil {
		return nil, fmt.Errorf(errResolverSilent, resolver.Name, control, err)
	}

	client.Zone = state.Zone

	// Disarmed before the baseline, because the baseline is measured through
	// this resolver and one still carrying a previous run's fault would make the
	// two phases see different topologies.
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

// startAuthority stands khaos's certificate authority up on BOTH of its
// listeners, before the baseline.
//
// Before the baseline and not before the fault, for the same reason the proxy
// and the provider are: the baseline is measured through this authority, so one
// that arrived at injection time would make the two phases see different
// topologies and the difference between them would be khaos rather than the
// fault.
//
// Both addresses come from the experiment's parameters, which the range answers
// and an operator can override. Nothing here is discovered, because the TLS
// gateway is already dialling a specific address and khaos does not get to pick
// a different one.
func startAuthority(
	out io.Writer,
	spec experiment.Experiment,
) error {
	if err := spec.Authority.Listen(spec.AuthorityListen); err != nil {
		return fmt.Errorf(errAuthorityBind, spec.AuthorityListen, err)
	}

	if err := spec.Authority.ListenTLS(spec.AuthorityTLS); err != nil {
		return fmt.Errorf(errAuthorityBind, spec.AuthorityTLS, err)
	}

	// An HONEST chain, minted before anything is probed. Without it the
	// authority has nothing armed, the baseline handshake falls back to a chain
	// built per connection, and the leaf's serial changes under the target
	// while khaos is trying to revoke it.
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

// portOf reads the port an issuer names. It is the one thing khaos needs from
// the issuer beyond minting under it, and a missing or unusable port is a
// refusal by name rather than a bind to something arbitrary.
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
	return name == experiment.ParamToken || name == experiment.ParamRevocable
}

// askTheRange goes and gets only what this invocation is actually missing. A
// second credential costs a round trip and the authority's address costs a
// container inspection, and an experiment that needs neither should pay for
// neither.
func askTheRange(
	ctx context.Context,
	reader rangelab.PortReader,
	lab rangelab.Lab,
	missing []string,
) (rangeAnswers, error) {
	answers := rangeAnswers{}
	want := func(name string) bool { return slices.Contains(missing, name) }

	if want(experiment.ParamToken) {
		token, err := lab.IssueToken(ctx)
		if err != nil {
			return rangeAnswers{}, err
		}
		answers.Token = token
	}

	// A SECOND credential, issued separately. The one khaos revokes has to be
	// distinct from the one it keeps presenting as valid, or revoking it would
	// take away the stream that proves the target is still serving at all and
	// every verdict would read as a crash.
	if want(experiment.ParamRevocable) {
		revocable, err := lab.IssueToken(ctx)
		if err != nil {
			return rangeAnswers{}, err
		}
		answers.Revocable = revocable
	}

	if want(experiment.ParamProxyListen) ||
		want(experiment.ParamProxyUpstream) {
		listen, upstream, err := lab.ProxyEndpoint(ctx, reader)
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

	// All four together, because a certificate experiment needs every one of
	// them and asking for them separately would let a run start with khaos
	// bound where the gateway is not looking.
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
