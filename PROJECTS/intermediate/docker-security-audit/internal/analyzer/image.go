/*
AngelaMos | 2026
image.go
*/

package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/benchmark"
	"github.com/CarterPerez-dev/docksec/internal/docker"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/docker/docker/api/types"
)

type ImageAnalyzer struct {
	client *docker.Client
}

func NewImageAnalyzer(client *docker.Client) *ImageAnalyzer {
	return &ImageAnalyzer{client: client}
}

func (a *ImageAnalyzer) Name() string {
	return "image"
}

func (a *ImageAnalyzer) Analyze(
	ctx context.Context,
) (finding.Collection, error) {
	images, err := a.client.ListImages(ctx)
	if err != nil {
		return nil, err
	}

	var findings finding.Collection
	for _, img := range images {
		info, err := a.client.InspectImage(ctx, img.ID)
		if err != nil {
			continue
		}

		name := img.ID[:12]
		if len(img.RepoTags) > 0 {
			name = img.RepoTags[0]
		}

		target := finding.Target{
			Type: finding.TargetImage,
			Name: name,
			ID:   img.ID,
		}

		findings = append(findings, a.analyzeImage(target, info)...)
	}

	return findings, nil
}

func (a *ImageAnalyzer) analyzeImage(
	target finding.Target,
	info types.ImageInspect,
) finding.Collection {
	var findings finding.Collection

	findings = append(findings, a.checkRootUser(target, info)...)
	findings = append(findings, a.checkHealthcheck(target, info)...)
	findings = append(findings, a.checkExposedPorts(target, info)...)

	return findings
}

func (a *ImageAnalyzer) checkRootUser(
	target finding.Target,
	info types.ImageInspect,
) finding.Collection {
	var findings finding.Collection

	if info.Config == nil {
		return findings
	}

	user := info.Config.User
	if user == "" || user == "root" || user == "0" {
		control, _ := benchmark.Get("4.1")
		f := finding.New("CIS-4.1", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryImage)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *ImageAnalyzer) checkHealthcheck(
	target finding.Target,
	info types.ImageInspect,
) finding.Collection {
	var findings finding.Collection

	if info.Config == nil {
		return findings
	}

	if info.Config.Healthcheck == nil ||
		len(info.Config.Healthcheck.Test) == 0 {
		control, _ := benchmark.Get("4.6")
		f := finding.New("CIS-4.6", control.Title, finding.SeverityLow, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryImage)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	if info.Config.Healthcheck != nil &&
		len(info.Config.Healthcheck.Test) > 0 {
		if info.Config.Healthcheck.Test[0] == "NONE" {
			control, _ := benchmark.Get("4.6")
			f := finding.New("CIS-4.6", "HEALTHCHECK explicitly disabled", finding.SeverityLow, target).
				WithDescription("Image has HEALTHCHECK set to NONE, disabling health monitoring.").
				WithCategory(string(CategoryImage)).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *ImageAnalyzer) checkExposedPorts(
	target finding.Target,
	info types.ImageInspect,
) finding.Collection {
	var findings finding.Collection

	if info.Config == nil || info.Config.ExposedPorts == nil {
		return findings
	}

	privilegedPorts := []string{}
	for port := range info.Config.ExposedPorts {
		portNum := strings.Split(string(port), "/")[0]
		if isPrivilegedPort(portNum) {
			privilegedPorts = append(privilegedPorts, portNum)
		}
	}

	if len(privilegedPorts) > 0 {
		f := finding.New("DS-IMG-PRIVPORT", "Image exposes privileged ports: "+strings.Join(privilegedPorts, ", "), finding.SeverityInfo, target).
			WithDescription("Image exposes ports below 1024 which typically require root privileges.").
			WithCategory(string(CategoryImage)).
			WithRemediation("Consider using non-privileged ports (>1024) and mapping them at runtime if needed.")
		findings = append(findings, f)
	}

	return findings
}

func isPrivilegedPort(port string) bool {
	var portNum int
	_, err := fmt.Sscanf(port, "%d", &portNum)
	if err != nil {
		return false
	}
	return portNum > 0 && portNum < 1024
}
