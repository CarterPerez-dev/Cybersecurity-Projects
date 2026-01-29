/*
AngelaMos | 2026
dockerfile.go
*/

package analyzer

import (
	"context"
	"os"
	"strings"

	"github.com/CarterPerez-dev/docksec/internal/benchmark"
	"github.com/CarterPerez-dev/docksec/internal/config"
	"github.com/CarterPerez-dev/docksec/internal/finding"
	"github.com/CarterPerez-dev/docksec/internal/rules"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

type DockerfileAnalyzer struct {
	path string
}

func NewDockerfileAnalyzer(path string) *DockerfileAnalyzer {
	return &DockerfileAnalyzer{path: path}
}

func (a *DockerfileAnalyzer) Name() string {
	return "dockerfile:" + a.path
}

func (a *DockerfileAnalyzer) Analyze(
	ctx context.Context,
) (finding.Collection, error) {
	file, err := os.Open(a.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	result, err := parser.Parse(file)
	if err != nil {
		return nil, err
	}

	target := finding.Target{
		Type: finding.TargetDockerfile,
		Name: a.path,
	}

	var findings finding.Collection

	findings = append(findings, a.checkUserInstruction(target, result.AST)...)
	findings = append(findings, a.checkHealthcheck(target, result.AST)...)
	findings = append(findings, a.checkAddInstruction(target, result.AST)...)
	findings = append(findings, a.checkSecrets(target, result.AST)...)
	findings = append(findings, a.checkLatestTag(target, result.AST)...)
	findings = append(findings, a.checkCurlPipe(target, result.AST)...)
	findings = append(findings, a.checkSudo(target, result.AST)...)

	return findings, nil
}

func (a *DockerfileAnalyzer) checkUserInstruction(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	hasUser := false
	var lastFromLine int

	for _, node := range ast.Children {
		switch strings.ToUpper(node.Value) {
		case "FROM":
			lastFromLine = node.StartLine
			hasUser = false
		case "USER":
			hasUser = true
			user := ""
			if node.Next != nil {
				user = node.Next.Value
			}
			if user == "root" || user == "0" {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("DS-USER-ROOT", "USER instruction sets root user", finding.SeverityMedium, target).
					WithDescription("Dockerfile explicitly sets USER to root, which should be avoided.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation("Create and use a non-root user in the Dockerfile.")
				findings = append(findings, f)
			}
		}
	}

	if !hasUser && lastFromLine > 0 {
		control, _ := benchmark.Get("4.1")
		loc := &finding.Location{Path: a.path, Line: lastFromLine}
		f := finding.New("CIS-4.1", control.Title, finding.SeverityMedium, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryDockerfile)).
			WithLocation(loc).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *DockerfileAnalyzer) checkHealthcheck(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	hasHealthcheck := false
	for _, node := range ast.Children {
		if strings.ToUpper(node.Value) == "HEALTHCHECK" {
			hasHealthcheck = true
			if node.Next != nil &&
				strings.ToUpper(node.Next.Value) == "NONE" {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				control, _ := benchmark.Get("4.6")
				f := finding.New("CIS-4.6", "HEALTHCHECK explicitly disabled", finding.SeverityLow, target).
					WithDescription("Dockerfile disables health checks with HEALTHCHECK NONE.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation(control.Remediation).
					WithReferences(control.References...).
					WithCISControl(control.ToCISControl())
				findings = append(findings, f)
			}
			break
		}
	}

	if !hasHealthcheck {
		control, _ := benchmark.Get("4.6")
		f := finding.New("CIS-4.6", control.Title, finding.SeverityLow, target).
			WithDescription(control.Description).
			WithCategory(string(CategoryDockerfile)).
			WithRemediation(control.Remediation).
			WithReferences(control.References...).
			WithCISControl(control.ToCISControl())
		findings = append(findings, f)
	}

	return findings
}

func (a *DockerfileAnalyzer) checkAddInstruction(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	for _, node := range ast.Children {
		if strings.ToUpper(node.Value) == "ADD" {
			src := ""
			if node.Next != nil {
				src = node.Next.Value
			}

			isURL := strings.HasPrefix(src, "http://") ||
				strings.HasPrefix(src, "https://")
			isArchive := strings.HasSuffix(src, ".tar") ||
				strings.HasSuffix(src, ".tar.gz") ||
				strings.HasSuffix(src, ".tgz") ||
				strings.HasSuffix(src, ".tar.bz2")

			if !isURL && !isArchive {
				control, _ := benchmark.Get("4.9")
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("CIS-4.9", control.Title, finding.SeverityLow, target).
					WithDescription(control.Description).
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation(control.Remediation).
					WithReferences(control.References...).
					WithCISControl(control.ToCISControl())
				findings = append(findings, f)
			}

			if isURL {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("DS-ADD-URL", "ADD instruction fetches from URL", finding.SeverityMedium, target).
					WithDescription("ADD with URLs can introduce security risks. Use curl/wget with verification instead.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation("Use RUN with curl or wget and verify checksums of downloaded files.")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (a *DockerfileAnalyzer) checkSecrets(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	for _, node := range ast.Children {
		cmd := strings.ToUpper(node.Value)
		if cmd != "ENV" && cmd != "ARG" && cmd != "RUN" && cmd != "LABEL" {
			continue
		}

		line := getFullLine(node)

		if cmd == "ENV" || cmd == "ARG" {
			varName := ""
			varValue := ""
			if node.Next != nil {
				parts := strings.SplitN(node.Next.Value, "=", 2)
				varName = parts[0]
				if len(parts) > 1 {
					varValue = parts[1]
				}
			}
			if rules.IsSensitiveEnvName(varName) {
				control, _ := benchmark.Get("4.10")
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("CIS-4.10", "Sensitive variable in "+cmd+": "+varName, finding.SeverityHigh, target).
					WithDescription(control.Description).
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation(control.Remediation).
					WithReferences(control.References...).
					WithCISControl(control.ToCISControl())
				findings = append(findings, f)
			}

			if varValue != "" &&
				rules.IsHighEntropyString(
					varValue,
					config.MinSecretLength,
					config.MinEntropyForSecret,
				) {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("DS-HIGH-ENTROPY", "High entropy string in "+cmd+" (potential secret)", finding.SeverityMedium, target).
					WithDescription("Value in " + varName + " has high entropy, indicating a potential hardcoded secret or key.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation("Use Docker secrets, build arguments, or environment variables at runtime instead of hardcoding sensitive values.")
				findings = append(findings, f)
			}
		}

		secrets := rules.DetectSecrets(line)
		for _, secret := range secrets {
			control, _ := benchmark.Get("4.10")
			loc := &finding.Location{Path: a.path, Line: node.StartLine}
			f := finding.New("CIS-4.10", "Potential "+string(secret.Type)+" detected in Dockerfile", finding.SeverityHigh, target).
				WithDescription(secret.Description + ". " + control.Description).
				WithCategory(string(CategoryDockerfile)).
				WithLocation(loc).
				WithRemediation(control.Remediation).
				WithReferences(control.References...).
				WithCISControl(control.ToCISControl())
			findings = append(findings, f)
		}
	}

	return findings
}

func (a *DockerfileAnalyzer) checkLatestTag(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	for _, node := range ast.Children {
		if strings.ToUpper(node.Value) == "FROM" {
			image := ""
			if node.Next != nil {
				image = node.Next.Value
			}

			if image != "" && !strings.Contains(image, ":") {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("DS-LATEST-TAG", "FROM uses implicit :latest tag", finding.SeverityMedium, target).
					WithDescription("Using implicit :latest tag makes builds non-reproducible and may introduce unexpected changes.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation("Pin images to specific versions or digests (e.g., alpine:3.18 or alpine@sha256:...).")
				findings = append(findings, f)
			}

			if strings.HasSuffix(image, ":latest") {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("DS-LATEST-TAG", "FROM uses explicit :latest tag", finding.SeverityMedium, target).
					WithDescription("Using :latest tag makes builds non-reproducible and may introduce unexpected changes.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation("Pin images to specific versions or digests (e.g., alpine:3.18 or alpine@sha256:...).")
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (a *DockerfileAnalyzer) checkCurlPipe(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	dangerousPatterns := []string{
		"curl|sh", "curl|bash", "wget|sh", "wget|bash",
		"curl | sh", "curl | bash", "wget | sh", "wget | bash",
	}

	for _, node := range ast.Children {
		if strings.ToUpper(node.Value) != "RUN" {
			continue
		}

		line := strings.ToLower(getFullLine(node))
		for _, pattern := range dangerousPatterns {
			if strings.Contains(line, pattern) {
				loc := &finding.Location{Path: a.path, Line: node.StartLine}
				f := finding.New("DS-CURL-PIPE", "Piping curl/wget to shell detected", finding.SeverityHigh, target).
					WithDescription("Piping downloaded content directly to a shell is dangerous and can execute malicious code.").
					WithCategory(string(CategoryDockerfile)).
					WithLocation(loc).
					WithRemediation("Download files first, verify checksums, then execute.")
				findings = append(findings, f)
				break
			}
		}
	}

	return findings
}

func (a *DockerfileAnalyzer) checkSudo(
	target finding.Target,
	ast *parser.Node,
) finding.Collection {
	var findings finding.Collection

	for _, node := range ast.Children {
		if strings.ToUpper(node.Value) != "RUN" {
			continue
		}

		line := getFullLine(node)
		if strings.Contains(line, "sudo ") {
			loc := &finding.Location{Path: a.path, Line: node.StartLine}
			f := finding.New("DS-SUDO", "sudo used in RUN instruction", finding.SeverityLow, target).
				WithDescription("Using sudo in Dockerfiles is usually unnecessary since commands run as root by default.").
				WithCategory(string(CategoryDockerfile)).
				WithLocation(loc).
				WithRemediation("Remove sudo from commands or use USER instruction to switch users.")
			findings = append(findings, f)
		}
	}

	return findings
}

func getFullLine(node *parser.Node) string {
	if node.Original != "" {
		return node.Original
	}

	var parts []string
	parts = append(parts, node.Value)
	for n := node.Next; n != nil; n = n.Next {
		parts = append(parts, n.Value)
	}
	return strings.Join(parts, " ")
}
