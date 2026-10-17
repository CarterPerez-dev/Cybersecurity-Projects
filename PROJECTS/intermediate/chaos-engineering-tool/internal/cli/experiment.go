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

	return inputs{Project: project, Supplied: supplied, Timing: timing}, nil
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

	accepted, err := work.Docker.Accept(
		ctx,
		spec.Fault.Target,
		dockerx.Filter{Project: project},
		guard,
	)
	if err != nil {
		return err
	}

	env, closeTiers, err := standUpTiers(
		ctx,
		out,
		work,
		&spec,
		accepted,
		dockerx.Filter{Project: project},
		guard,
	)

	// BEFORE the error check, because standUpTiers hands the closer back WITH
	// its error: a tier that failed is one position past tiers that already
	// bound a listener, and khaos's claim that nothing is left listening has to
	// hold by construction rather than because the process happens to exit.
	defer closeTiers()

	if err != nil {
		return err
	}

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
// contract: the state of the operator's system outranks the verdict about it.
func exitFor(result experiment.Result, runErr error) error {
	if runErr != nil {
		return runErr
	}

	if result.Observation.RollbackFailed {
		return run.ErrRevertFailed
	}

	if result.Verdict.Recovery == experiment.Degraded {
		return ErrNotRecovered
	}

	if result.Verdict.Defect {
		return ErrDefectFound
	}

	if !conclusive(result.Verdict.Epistemic) {
		return fmt.Errorf(
			errInconclusive,
			ErrInconclusive,
			result.Verdict.Epistemic,
		)
	}

	if !result.Verdict.Conclusive {
		return fmt.Errorf(errInconclusive, ErrInconclusive, verdictThinEvidence)
	}

	if result.Verdict.Recovery == experiment.Unobserved {
		return fmt.Errorf(
			errInconclusive,
			ErrInconclusive,
			verdictRecoveryUnobserved,
		)
	}

	return nil
}

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
)

func tierOf(kind string) tier {
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
}

func answersFor(lab rangelab.Lab, at tier) tierAnswers {
	answers := tierAnswers{
		url:    lab.ProtectedURL(),
		target: rangelab.IDPName,
	}

	switch at {
	case tierProxy:
		answers.url = lab.ProxiedProtectedURL()

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

	// The target IS the engine here. Nothing of the operator's is mutated: the
	// fault acts on a role khaos mints on that engine for the run. PostgreSQL
	// is the zero-flag default because its own image carries the loopback
	// `trust` rule that research 07 section 6.1 measured a probe through, so
	// it is the engine where khaos's negative control earns its keep.
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
	at := tierOf(definition.FaultKind)

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

// requireTier refuses before the baseline when the running range is missing the
// part this experiment needs, rather than letting the run report a fixture that
// is not there as a target that was not enforcing. That is the M4 finding, and
// each tier has arrived at it through its own door.
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

	fault, err := proxy.Open(listen, upstream)
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
			return standUpProxyTier(ctx, out, work.Docker, spec, &env)
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

	env.Proxy = fault
	env.ProxyFault = *spec.ProxyFault

	return func() { _ = fault.Close() }, nil
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
) (func(), error) {
	if spec.Cred == nil {
		return nil, nil
	}

	plan, err := openCredTier(ctx, out, docker, *spec, target, sources)
	if err != nil {
		return nil, err
	}

	env.Cred = spec.Cred.Tier
	env.CredTrap = spec.Cred.Tier.Trap()
	env.CredPlan = plan

	return func() {
		_ = spec.Cred.Tier.Close(context.WithoutCancel(ctx))
	}, nil
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

	plan, subject, err := credRecipe(cred, config, engine, target, environ)
	if err != nil {
		return inject.CredPlan{}, err
	}

	if err := cred.Tier.Open(ctx, config, subject); err != nil {
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
) error {
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
	return name == experiment.ParamToken || name == experiment.ParamRevocable
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
