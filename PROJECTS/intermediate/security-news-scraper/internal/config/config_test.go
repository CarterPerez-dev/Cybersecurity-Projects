// ©AngelaMos | 2026
// config_test.go

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultHasSaneValues(t *testing.T) {
	c := Default()
	if c.DBPath != defaultDBPath {
		t.Errorf("db_path = %q, want %q", c.DBPath, defaultDBPath)
	}
	if c.AI.Enabled {
		t.Error("ai.enabled must default to false (opt-in)")
	}
	if c.AI.Provider != "qwen" {
		t.Errorf("ai.provider = %q, want qwen", c.AI.Provider)
	}
	if c.AI.Qwen.Model != defaultQwenModel {
		t.Errorf("qwen model = %q, want %q", c.AI.Qwen.Model, defaultQwenModel)
	}
	sum := c.Rank.Weights.Recency + c.Rank.Weights.CVSS + c.Rank.Weights.KEV +
		c.Rank.Weights.EPSS + c.Rank.Weights.Velocity + c.Rank.Weights.Source +
		c.Rank.Weights.Keyword
	if sum < 0.99 || sum > 1.01 {
		t.Errorf("rank weights sum = %v, want ~1.0", sum)
	}
}

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if c.DBPath != defaultDBPath {
		t.Errorf("missing file should yield defaults, got db_path %q", c.DBPath)
	}
}

func TestLoadOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
db_path: /tmp/custom.db
watchlist: [fortinet, "cisco ios"]
fetch:
  workers: 4
ai:
  enabled: true
  provider: anthropic
  anthropic:
    model: claude-sonnet-4-6
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.DBPath != "/tmp/custom.db" {
		t.Errorf("db_path = %q, want /tmp/custom.db", c.DBPath)
	}
	if len(c.Watchlist) != 2 || c.Watchlist[0] != "fortinet" {
		t.Errorf("watchlist = %v", c.Watchlist)
	}
	if c.Fetch.Workers != 4 {
		t.Errorf("workers = %d, want 4", c.Fetch.Workers)
	}
	if !c.AI.Enabled || c.AI.Provider != "anthropic" {
		t.Errorf("ai override failed: %+v", c.AI)
	}
	if c.AI.Anthropic.Model != "claude-sonnet-4-6" {
		t.Errorf("anthropic model = %q, want claude-sonnet-4-6", c.AI.Anthropic.Model)
	}
	if c.AI.Qwen.Model != defaultQwenModel {
		t.Errorf("unset qwen model should keep default, got %q", c.AI.Qwen.Model)
	}
}

func TestValidateRejectsBadProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("ai:\n  provider: llama\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid ai.provider")
	}
}

func TestValidateRejectsLookbackBelowWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lb.yaml")
	body := "cluster:\n  window_hours: 72\n  lookback_hours: 24\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected error when lookback_hours < window_hours")
	}
}
