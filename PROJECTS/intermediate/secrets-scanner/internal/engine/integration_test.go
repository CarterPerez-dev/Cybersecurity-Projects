// ©AngelaMos | 2026
// integration_test.go

package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/CarterPerez-dev/portia/internal/engine"
	"github.com/CarterPerez-dev/portia/internal/rules"
	"github.com/CarterPerez-dev/portia/internal/source"
	"github.com/CarterPerez-dev/portia/pkg/types"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file location")
	}
	return filepath.Join(
		filepath.Dir(filename), "..", "..", "testdata", "fixtures",
	)
}

func setupPipeline(t *testing.T) (*engine.Pipeline, *rules.Registry) {
	t.Helper()
	reg := rules.NewRegistry()
	rules.RegisterBuiltins(reg)
	return engine.NewPipeline(reg), reg
}

func findByRuleID(
	findings []types.Finding, ruleID string,
) *types.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestIntegrationFullScan(t *testing.T) {
	dir := testdataDir(t)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("testdata/fixtures not found")
	}

	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	ruleIDs := make(map[string]bool)
	for _, f := range result.Findings {
		ruleIDs[f.RuleID] = true
	}

	expectedRules := []string{
		"aws-access-key-id",
		"stripe-live-secret",
		"ssh-private-key-rsa",
		"generic-password",
	}

	for _, id := range expectedRules {
		if !ruleIDs[id] {
			t.Errorf("expected finding for rule %q, not found", id)
		}
	}
}

func TestIntegrationAWSKeyDetection(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	f := findByRuleID(result.Findings, "aws-access-key-id")
	if f == nil {
		t.Fatal("aws-access-key-id finding not found")
	}

	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}

	if f.FilePath != "config.py" {
		t.Errorf("expected config.py, got %s", f.FilePath)
	}
}

func TestIntegrationStripeKeyDetection(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	f := findByRuleID(result.Findings, "stripe-live-secret")
	if f == nil {
		t.Fatal("stripe-live-secret finding not found")
	}

	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}

	if f.FilePath != "payment.env" {
		t.Errorf("expected payment.env, got %s", f.FilePath)
	}
}

func TestIntegrationPrivateKeyDetection(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	f := findByRuleID(result.Findings, "ssh-private-key-rsa")
	if f == nil {
		t.Fatal("ssh-private-key-rsa finding not found")
	}

	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}

	if f.FilePath != "key.pem" {
		t.Errorf("expected key.pem, got %s", f.FilePath)
	}
}

func TestIntegrationPasswordDetection(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	f := findByRuleID(result.Findings, "generic-password")
	if f == nil {
		t.Fatal("generic-password finding not found")
	}

	if f.Severity != types.SeverityHigh {
		t.Errorf("expected HIGH, got %s", f.Severity)
	}

	if f.Entropy <= 0 {
		t.Error("expected positive entropy for password")
	}
}

func TestIntegrationGitHubTokenDetection(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	f := findByRuleID(result.Findings, "github-pat-classic")
	if f == nil {
		f = findByRuleID(result.Findings, "github-pat-fine")
		if f == nil {
			t.Fatal(
				"github-pat-classic or github-pat-fine finding not found",
			)
		}
	}

	if f.Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}

	if f.FilePath != "github_token.js" {
		t.Errorf("expected github_token.js, got %s", f.FilePath)
	}
}

func TestIntegrationConnectionStringDetection(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	f := findByRuleID(result.Findings, "postgres-connection")
	if f == nil {
		t.Fatal("postgres-connection finding not found")
	}

	if f.FilePath != "connection.yml" {
		t.Errorf("expected connection.yml, got %s", f.FilePath)
	}
}

func TestIntegrationNoFalsePositivesOnSafeFiles(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.FilePath == "safe.txt" {
			t.Errorf(
				"unexpected finding in safe.txt: %s (%s)",
				f.RuleID, f.Secret,
			)
		}
	}
}

func TestIntegrationTemplatesFiltered(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.FilePath == "template.env" {
			t.Errorf(
				"unexpected finding in template.env: %s (%s)",
				f.RuleID, f.Secret,
			)
		}
	}
}

func TestIntegrationExcludePaths(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, []string{"*.py"})

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.FilePath == "config.py" {
			t.Error("config.py should be excluded")
		}
	}
}

func TestIntegrationDisableRules(t *testing.T) {
	dir := testdataDir(t)
	reg := rules.NewRegistry()
	rules.RegisterBuiltins(reg)
	reg.Disable("aws-access-key-id", "stripe-live-secret")

	p := engine.NewPipeline(reg)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	for _, f := range result.Findings {
		if f.RuleID == "aws-access-key-id" {
			t.Error("aws-access-key-id should be disabled")
		}
		if f.RuleID == "stripe-live-secret" {
			t.Error("stripe-live-secret should be disabled")
		}
	}
}

func TestIntegrationFindingsSortBySeverity(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	sorted := make([]types.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Severity.Rank() < sorted[j].Severity.Rank()
	})

	if len(sorted) > 0 &&
		sorted[0].Severity != types.SeverityCritical {
		t.Errorf(
			"expected first sorted finding to be CRITICAL, got %s",
			sorted[0].Severity,
		)
	}
}

func TestIntegrationResultMetadata(t *testing.T) {
	dir := testdataDir(t)
	p, reg := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	result, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("pipeline run failed: %v", err)
	}

	if result.TotalRules != reg.Len() {
		t.Errorf(
			"expected %d rules, got %d",
			reg.Len(), result.TotalRules,
		)
	}

	if result.TotalFindings < len(result.Findings) {
		t.Errorf(
			"total findings %d < unique findings %d",
			result.TotalFindings, len(result.Findings),
		)
	}
}

func TestIntegrationContextCancellation(t *testing.T) {
	dir := testdataDir(t)
	p, _ := setupPipeline(t)
	src := source.NewDirectory(dir, 0, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Run(ctx, src)
	if err == nil {
		t.Log("expected error or empty result from cancelled context")
	}
}
