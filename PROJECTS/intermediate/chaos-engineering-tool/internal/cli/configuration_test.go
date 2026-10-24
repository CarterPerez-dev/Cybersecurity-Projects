// ©AngelaMos | 2026
// configuration_test.go

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/record"
	"github.com/CarterPerez-dev/khaos/internal/statedir"
	"gopkg.in/yaml.v3"
)

func TestRecordReplayAndYAMLKeepParametersWithoutSecrets(t *testing.T) {
	params := map[string]string{
		"target":        "owned",
		"url":           "http://127.0.0.1:45000/check",
		"token":         "private-valid-value",
		"invalid-token": "private-invalid-value",
	}
	first, err := experiment.Build(
		experiment.NameDependencyOutage, params, experiment.Timing{},
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range params {
		t.Setenv(envFor(name), value)
	}
	definition, _ := experiment.Lookup(first.Name)
	rec := record.Of("test", experiment.Result{
		Experiment: first.Name, Configuration: first.Configuration,
	}, definition, 0, "")
	dir := t.TempDir()
	if _, err := record.Write(dir, rec, nil); err != nil {
		t.Fatal(err)
	}
	encoded, err := yaml.Marshal(first.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "experiment.yaml")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		path   string
		replay bool
	}{
		{path, false}, {filepath.Join(dir, record.RecordFile), true},
	} {
		config, err := loadConfiguration(input.path, input.replay)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(config)
		if strings.Contains(string(body), "private-") {
			t.Fatal("secret value entered the configuration")
		}
		resolved, timing, err := config.Resolve(os.LookupEnv)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt, err := experiment.Build(config.Experiment, resolved, timing)
		if err != nil ||
			!reflect.DeepEqual(rebuilt.Configuration, first.Configuration) {
			t.Fatalf("replay differs: %v", err)
		}
		if _, _, err := config.Resolve(
			func(string) (string, bool) { return "", false },
		); err == nil {
			t.Fatal("replay silently substituted a missing credential")
		}
	}
}

func TestRunsShowAndEventsIntegrity(t *testing.T) {
	t.Setenv(statedir.EnvStateDir, t.TempDir())
	paths, err := statedir.Default()
	if err != nil {
		t.Fatal(err)
	}
	result, definition := emitted(t)
	result.RunID = "saved-run"
	rec := record.Of("test", result, definition, 0, "")
	if _, err := record.Write(paths.Run(result.RunID), rec, nil); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"runs"}, {"show", result.RunID}} {
		root, out := NewRoot(), &strings.Builder{}
		root.SetOut(out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), result.RunID) {
			t.Fatal("saved run is missing from output")
		}
	}
	if err := os.WriteFile(
		filepath.Join(paths.Run(result.RunID), record.EventsFile),
		[]byte("tampered"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Read(
		filepath.Join(paths.Run(result.RunID), record.RecordFile),
	); err == nil {
		t.Fatal("modified events passed integrity verification")
	}
}

func TestReplayRefusesTargetReplacement(t *testing.T) {
	expected := experiment.Identity{ID: "original", ImageID: "sha256:original"}
	target := dockerx.Target{ID: expected.ID, ImageID: expected.ImageID}
	if err := verifyReplayTarget(
		expected, target, &dockerx.Client{},
	); err != nil {
		t.Fatal(err)
	}
	target.ImageID = "sha256:replacement"
	if err := verifyReplayTarget(
		expected, target, &dockerx.Client{},
	); err == nil {
		t.Fatal("replay accepted a different image")
	}
}

func TestYAMLRejectsUnknownSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(
		path, []byte("schema_version: 1\nabort_aftr: 3\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfiguration(path, false); err == nil {
		t.Fatal("misspelled stop rule was ignored")
	}
}
