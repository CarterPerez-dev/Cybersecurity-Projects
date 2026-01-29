/*
AngelaMos | 2026
container.go
*/

package analyzer

import (
	"context"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/benchmark"
	"github.com/CarterPerez-dev/docksec/internal/docker"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/CarterPerez-dev/docksec/internal/rules"
	"github.com/docker/docker/api/types"
)

type ContainerAnalyzer struct {
	client *docker.Client
}

func NewContainerAnalyzer(client *docker.Client) *ContainerAnalyzer {
	return &ContainerAnalyzer{client: client}
}

func (a *ContainerAnalyzer) Name() string {
	return "container"
}

func (a *ContainerAnalyzer) Analyze(
	ctx context.Context,
) (finding.Collection, error) {
	containers, err := a.client.ListContainers(ctx, true)
	if err != nil {
		return nil, err
	}

	var findings finding.Collection
	for _, c := range containers {
		info, err := a.client.InspectContainer(ctx, c.ID)
		if err != nil {
			continue
		}
		findings = append(findings, a.analyzeContainer(info)...)
	}

	return findings, nil
}

func (a *ContainerAnalyzer) analyzeContainer(
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection
	target := finding.Target{
		Type: finding.TargetContainer,
		Name: strings.TrimPrefix(info.Name, "/"),
		ID:   info.ID,
	}

	if info.HostConfig == nil {
		return findings
	}

	findings = append(findings, a.checkPrivileged(target, info)...)
	findings = append(findings, a.checkCapabilities(target, info)...)
	findings = append(findings, a.checkMounts(target, info)...)
	findings = append(findings, a.checkNamespaces(target, info)...)
	findings = append(findings, a.checkSecurityOptions(target, info)...)
	findings = append(findings, a.checkResourceLimits(target, info)...)
	findings = append(findings, a.checkReadonlyRootfs(target, info)...)

	return findings
}

func (a *ContainerAnalyzer) checkPrivileged(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	if info.HostConfig.Privileged {
		control, _ := benchmark.Get("5.4")
		f := finding.New("CIS-5.4", control.Title, finding.SeverityCritical, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkCapabilities(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	for _, cap := range info.HostConfig.CapAdd {
		capName := strings.ToUpper(string(cap))
		capInfo, exists := rules.GetCapabilityInfo(capName)
		if !exists {
			continue
		}

		if capInfo.Severity >= finding.SeverityHigh {
			control, _ := benchmark.Get("5.3")
			title := "Dangerous capability added: " + capName
			if capInfo.Severity == finding.SeverityCritical {
				title = "Critical capability added: " + capName
			}
			f := finding.New("CIS-5.3", title, capInfo.Severity, target).
				WithDescription(capInfo.Description).
				WithCategory(string(CategoryContainerRuntime)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ContainerAnalyzer) checkMounts(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	for _, mount := range info.Mounts {
		source := mount.Source

		if rules.IsDockerSocket(source) {
			control, _ := benchmark.Get("5.31")
			pathInfo, _ := rules.GetPathInfo(source)
			f := finding.New("CIS-5.31", control.Title, finding.SeverityCritical, target).
				WithDescription(pathInfo.Description).
				WithCategory(string(CategoryContainerRuntime)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())
			findings = append(findings, f)
			continue
		}

		if rules.IsSensitivePath(source) {
			control, _ := benchmark.Get("5.5")
			pathInfo, _ := rules.GetPathInfo(source)
			severity := rules.GetPathSeverity(source)

			description := control.Description
			if pathInfo.Description != "" {
				description = pathInfo.Description
			}

			f := finding.New("CIS-5.5", "Sensitive host path mounted: "+source, severity, target).
				WithDescription(description).
				WithCategory(string(CategoryContainerRuntime)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ContainerAnalyzer) checkNamespaces(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	if info.HostConfig.NetworkMode == "host" {
		control, _ := benchmark.Get("5.9")
		f := finding.New("CIS-5.9", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.PidMode == "host" {
		control, _ := benchmark.Get("5.15")
		f := finding.New("CIS-5.15", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.IpcMode == "host" {
		control, _ := benchmark.Get("5.16")
		f := finding.New("CIS-5.16", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.UTSMode == "host" {
		control, _ := benchmark.Get("5.20")
		f := finding.New("CIS-5.20", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkSecurityOptions(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	hasAppArmor := false
	hasSeccomp := false
	hasNoNewPrivileges := false
	seccompDisabled := false

	for _, opt := range info.HostConfig.SecurityOpt {
		if strings.HasPrefix(opt, "apparmor=") {
			hasAppArmor = true
		}
		if strings.HasPrefix(opt, "seccomp=") {
			hasSeccomp = true
			if opt == "seccomp=unconfined" {
				seccompDisabled = true
			}
		}
		if opt == "no-new-privileges" || opt == "no-new-privileges:true" {
			hasNoNewPrivileges = true
		}
	}

	if !hasAppArmor && !info.HostConfig.Privileged {
		control, _ := benchmark.Get("5.1")
		f := finding.New("CIS-5.1", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if seccompDisabled {
		control, _ := benchmark.Get("5.21")
		f := finding.New("CIS-5.21", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if !hasSeccomp && !info.HostConfig.Privileged {
		control, _ := benchmark.Get("5.21")
		f := finding.New("CIS-5.21", "No seccomp profile set", finding.SeverityMedium, target).
			WithDescription("Container is running without an explicit seccomp profile. While Docker applies a default profile, it's recommended to explicitly set one.").
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if !hasNoNewPrivileges {
		control, _ := benchmark.Get("5.25")
		f := finding.New("CIS-5.25", control.Title, finding.SeverityHigh, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkResourceLimits(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	if info.HostConfig.Memory == 0 {
		control, _ := benchmark.Get("5.10")
		f := finding.New("CIS-5.10", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.NanoCPUs == 0 && info.HostConfig.CPUShares == 0 &&
		info.HostConfig.CPUPeriod == 0 {
		control, _ := benchmark.Get("5.11")
		f := finding.New("CIS-5.11", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.HostConfig.PidsLimit == nil || *info.HostConfig.PidsLimit == 0 ||
		*info.HostConfig.PidsLimit == -1 {
		control, _ := benchmark.Get("5.28")
		f := finding.New("CIS-5.28", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ContainerAnalyzer) checkReadonlyRootfs(
	target finding.Target,
	info types.ContainerJSON,
) finding.Collection {
	var findings finding.Collection

	if !info.HostConfig.ReadonlyRootfs {
		control, _ := benchmark.Get("5.12")
		f := finding.New("CIS-5.12", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryContainerRuntime)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}
