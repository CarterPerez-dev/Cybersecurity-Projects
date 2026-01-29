/*
CarterPerez-dev | 2026
visitor.go
*/

package parser

import (
	"github.com/CarterPerez-dev/docksec/internal/finding"
)

type RuleVisitor struct {
	Target   finding.Target
	Findings finding.Collection
	rules    []Rule
}

type Rule interface {
	ID() string
	Check(ctx *RuleContext) []*finding.Finding
}

type RuleContext struct {
	Target      finding.Target
	Dockerfile  *DockerfileAST
	ComposeFile *ComposeFile
}

func NewRuleVisitor(target finding.Target, rules ...Rule) *RuleVisitor {
	return &RuleVisitor{
		Target: target,
		rules:  rules,
	}
}

func (v *RuleVisitor) VisitDockerfile(ast *DockerfileAST) {
	ctx := &RuleContext{
		Target:     v.Target,
		Dockerfile: ast,
	}

	for _, rule := range v.rules {
		findings := rule.Check(ctx)
		v.Findings = append(v.Findings, findings...)
	}
}

func (v *RuleVisitor) VisitCompose(cf *ComposeFile) {
	ctx := &RuleContext{
		Target:      v.Target,
		ComposeFile: cf,
	}

	for _, rule := range v.rules {
		findings := rule.Check(ctx)
		v.Findings = append(v.Findings, findings...)
	}
}

func (v *RuleVisitor) VisitCommand(cmd Command) {
}

func (v *RuleVisitor) VisitService(name string, svc *Service) {
}

func (v *RuleVisitor) Results() finding.Collection {
	return v.Findings
}

type BaseRule struct {
	RuleID      string
	Title       string
	Severity    finding.Severity
	Category    string
	Description string
	Remediation string
	References  []string
}

func (r *BaseRule) ID() string {
	return r.RuleID
}

func (r *BaseRule) NewFinding(target finding.Target) *finding.Finding {
	return finding.New(r.RuleID, r.Title, r.Severity, target).
		WithDescription(r.Description).
		WithCategory(r.Category).
		WithRemediation(r.Remediation).
		WithReferences(r.References...)
}

type DockerfileRule struct {
	BaseRule
	CheckFunc func(ast *DockerfileAST, target finding.Target) []*finding.Finding
}

func (r *DockerfileRule) Check(ctx *RuleContext) []*finding.Finding {
	if ctx.Dockerfile == nil {
		return nil
	}
	return r.CheckFunc(ctx.Dockerfile, ctx.Target)
}

type ComposeRule struct {
	BaseRule
	CheckFunc func(cf *ComposeFile, target finding.Target) []*finding.Finding
}

func (r *ComposeRule) Check(ctx *RuleContext) []*finding.Finding {
	if ctx.ComposeFile == nil {
		return nil
	}
	return r.CheckFunc(ctx.ComposeFile, ctx.Target)
}

type MultiRule struct {
	BaseRule
	DockerfileCheck func(ast *DockerfileAST, target finding.Target) []*finding.Finding
	ComposeCheck    func(cf *ComposeFile, target finding.Target) []*finding.Finding
}

func (r *MultiRule) Check(ctx *RuleContext) []*finding.Finding {
	var findings []*finding.Finding

	if ctx.Dockerfile != nil && r.DockerfileCheck != nil {
		findings = append(
			findings,
			r.DockerfileCheck(ctx.Dockerfile, ctx.Target)...)
	}

	if ctx.ComposeFile != nil && r.ComposeCheck != nil {
		findings = append(
			findings,
			r.ComposeCheck(ctx.ComposeFile, ctx.Target)...)
	}

	return findings
}
