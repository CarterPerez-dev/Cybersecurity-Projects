/*
AngelaMos | 2026
daemon.go
*/

package analyzer

import (
	"context"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/benchmark"
	"github.com/CarterPerez-dev/docksec/internal/docker"
	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type DaemonAnalyzer struct {
	client *docker.Client
}

func NewDaemonAnalyzer(client *docker.Client) *DaemonAnalyzer {
	return &DaemonAnalyzer{client: client}
}

func (a *DaemonAnalyzer) Name() string {
	return "daemon"
}

func (a *DaemonAnalyzer) Analyze(
	ctx context.Context,
) (finding.Collection, error) {
	info, err := a.client.Info(ctx)
	if err != nil {
		return nil, err
	}

	target := finding.Target{
		Type: finding.TargetDaemon,
		Name: "docker-daemon",
		ID:   info.ID,
	}

	var findings finding.Collection

	findings = append(
		findings,
		a.checkSeccompDefault(target, info.SecurityOptions)...)
	findings = append(
		findings,
		a.checkLiveRestore(target, info.LiveRestoreEnabled)...)
	findings = append(
		findings,
		a.checkExperimental(target, info.ExperimentalBuild)...)
	findings = append(
		findings,
		a.checkUsernsRemap(target, info.SecurityOptions)...)
	findings = append(
		findings,
		a.checkLoggingDriver(target, info.LoggingDriver)...)
	findings = append(
		findings,
		a.checkCgroupDriver(target, info.CgroupDriver)...)

	return findings, nil
}

func (a *DaemonAnalyzer) checkSeccompDefault(
	target finding.Target,
	securityOpts []string,
) finding.Collection {
	var findings finding.Collection

	seccompEnabled := false
	for _, opt := range securityOpts {
		if strings.HasPrefix(opt, "seccomp") {
			seccompEnabled = true
			if strings.Contains(opt, "unconfined") {
				control, _ := benchmark.Get("2.7")
				f := finding.New("CIS-2.7", control.Title, finding.SeverityHigh, target).
					WithDescription(control.Description).
					WithCategory(string(CategoryDaemon)).
					WithRemediation(control.Remediation).
					WithReferences(control.References...).
					WithCISControl(control.ToCISControl())
				findings = append(findings, f)
			}
			break
		}
	}

	if !seccompEnabled {
		control, _ := benchmark.Get("2.7")
		f := finding.New("CIS-2.7", "Seccomp not enabled on daemon", finding.SeverityMedium, target).
			WithDescription("Docker daemon is not configured with seccomp support.").
			WithCategory(string(CategoryDaemon)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *DaemonAnalyzer) checkLiveRestore(
	target finding.Target,
	enabled bool,
) finding.Collection {
	var findings finding.Collection

	if !enabled {
		control, _ := benchmark.Get("2.14")
		f := finding.New("CIS-2.14", control.Title, finding.SeverityLow, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryDaemon)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *DaemonAnalyzer) checkExperimental(
	target finding.Target,
	enabled bool,
) finding.Collection {
	var findings finding.Collection

	if enabled {
		control, _ := benchmark.Get("2.8")
		f := finding.New("CIS-2.8", control.Title, finding.SeverityLow, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryDaemon)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *DaemonAnalyzer) checkUsernsRemap(
	target finding.Target,
	securityOpts []string,
) finding.Collection {
	var findings finding.Collection

	usernsEnabled := false
	for _, opt := range securityOpts {
		if strings.HasPrefix(opt, "userns") {
			usernsEnabled = true
			break
		}
	}

	if !usernsEnabled {
		f := finding.New("CIS-2.8", "User namespace remapping not enabled", finding.SeverityInfo, target).
			WithDescription("User namespace remapping provides additional isolation by mapping container users to unprivileged host users.").
			WithCategory(string(CategoryDaemon)).
			WithRemediation("Configure --userns-remap in daemon.json for additional container isolation.")
		findings = append(findings, f)
	}

	return findings
}

func (a *DaemonAnalyzer) checkLoggingDriver(
	target finding.Target,
	driver string,
) finding.Collection {
	var findings finding.Collection

	if driver == "" || driver == "none" {
		control, _ := benchmark.Get("2.3")
		f := finding.New("CIS-2.3", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryDaemon)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *DaemonAnalyzer) checkCgroupDriver(
	target finding.Target,
	driver string,
) finding.Collection {
	var findings finding.Collection

	if driver == "" {
		f := finding.New("DS-CGROUP-001", "No cgroup driver configured", finding.SeverityInfo, target).
			WithDescription("Docker daemon has no explicit cgroup driver configured. This is informational.").
			WithCategory(string(CategoryDaemon)).
			WithRemediation("Consider explicitly configuring cgroup driver for consistency.")
		findings = append(findings, f)
	}

	return findings
}
