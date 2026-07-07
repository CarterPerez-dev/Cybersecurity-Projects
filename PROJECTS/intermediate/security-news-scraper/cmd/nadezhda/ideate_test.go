// ©AngelaMos | 2026
// ideate_test.go

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/setup"
	"github.com/CarterPerez-dev/nadezhda/internal/store"
)

func seedCluster(t *testing.T, st *store.Store) {
	t.Helper()
	stmts := []string{
		`INSERT INTO sources (id, name, url, type, weight, enabled) VALUES (1, 'krebs', 'https://krebsonsecurity.com', 'rss', 1.0, 1)`,
		`INSERT INTO articles (id, source_id, canonical_url, content_hash, title, published_at) VALUES (1, 1, 'https://krebsonsecurity.com/a', 'h1', 'Critical RCE exploited in the wild', 1000)`,
		`INSERT INTO clusters (id, cluster_key, first_seen, last_seen, size) VALUES (1, 'k1', 900, 1000, 1)`,
		`INSERT INTO cluster_members (cluster_id, article_id) VALUES (1, 1)`,
	}
	for _, s := range stmts {
		if _, err := st.DB().Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
}

func TestIdeateCommandEndToEnd(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(setup.EnvProvider, "")
	t.Setenv(setup.EnvQwenURL, "")
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	seedCluster(t, st)
	st.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{
				"content": `{"summary":"a critical rce","why":"widely exploited","angles":["hook one","hook two","hook three"],"format":"newsletter"}`,
			}}},
		})
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	cfgPath := filepath.Join(dir, "config.yaml")
	cfgYAML := "ai:\n  enabled: true\n  provider: qwen\n  qwen:\n    base_url: " + srv.URL + "\n    model: qwen2.5:7b\n"
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	prevCfg, prevDB, prevTop, prevProv, prevForce, prevSince := flagConfig, flagDB, ideateTop, ideateProvider, ideateForce, ideateSince
	defer func() {
		flagConfig, flagDB, ideateTop, ideateProvider, ideateForce, ideateSince = prevCfg, prevDB, prevTop, prevProv, prevForce, prevSince
	}()
	flagConfig, flagDB, ideateTop, ideateProvider, ideateForce, ideateSince = cfgPath, dbPath, 1, "", false, ""

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runIdeate(cmd, nil); err != nil {
		t.Fatalf("runIdeate: %v\noutput:\n%s", err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"ideated 1", "a critical rce", "hook one", "newsletter"} {
		if !strings.Contains(out, want) {
			t.Errorf("ideate output missing %q\n---\n%s", want, out)
		}
	}

	st2, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := st2.AINoteExists(1, "qwen")
	st2.Close()
	if err != nil || !ok {
		t.Fatalf("note not persisted: ok=%v err=%v", ok, err)
	}

	buf.Reset()
	if err := runIdeate(cmd, nil); err != nil {
		t.Fatalf("second runIdeate: %v", err)
	}
	if !strings.Contains(buf.String(), "skip cluster 1") {
		t.Errorf("second run should skip existing note:\n%s", buf.String())
	}

	buf.Reset()
	ideateForce = true
	if err := runIdeate(cmd, nil); err != nil {
		t.Fatalf("force runIdeate: %v", err)
	}
	if !strings.Contains(buf.String(), "ideated 1") {
		t.Errorf("--force should regenerate, not skip:\n%s", buf.String())
	}
}

func TestIdeateDisabledErrors(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(setup.EnvProvider, "")
	t.Setenv(setup.EnvQwenURL, "")
	prevCfg, prevProv := flagConfig, ideateProvider
	defer func() { flagConfig, ideateProvider = prevCfg, prevProv }()
	flagConfig, ideateProvider = "", ""

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetIn(strings.NewReader(""))

	err := runIdeate(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "not set up") {
		t.Fatalf("expected a 'not set up' error, got %v", err)
	}
}
