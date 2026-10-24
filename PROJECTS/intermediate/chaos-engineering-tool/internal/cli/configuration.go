// ©AngelaMos | 2026
// configuration.go

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/experiment"
	"github.com/CarterPerez-dev/khaos/internal/lease"
	"github.com/CarterPerez-dev/khaos/internal/record"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func attachConfiguration(
	spec *experiment.Experiment,
	given inputs,
	target dockerx.Target,
	daemon *dockerx.Client,
) {
	spec.Configuration.Project = given.Project
	spec.Configuration.AbortAfter = given.AbortAfter
	spec.Configuration.Target = experiment.Identity{
		ID: target.ID, Image: target.Image, ImageID: target.ImageID,
		Daemon: daemon.Daemon(),
	}
	spec.Configuration.Versions = map[string]string{
		"go": runtime.Version(), "docker_api": daemon.APIVersion(),
	}
	if version := daemon.ServerVersion(); version != "" {
		spec.Configuration.Versions["docker_engine"] = version
	}
}

func verifyReplayTarget(
	expected experiment.Identity,
	target dockerx.Target,
	daemon *dockerx.Client,
) error {
	for _, field := range []struct{ name, want, got string }{
		{"container ID", expected.ID, target.ID},
		{"image ID", expected.ImageID, target.ImageID},
		{"daemon ID", expected.Daemon, daemon.Daemon()},
	} {
		if field.want != "" && field.want != field.got {
			return fmt.Errorf(
				"replay %s changed: recorded %s, current %s",
				field.name, field.want, field.got,
			)
		}
	}
	return nil
}

func loadConfiguration(
	path string,
	replay bool,
) (experiment.Configuration, error) {
	if replay {
		rec, err := record.Read(path)
		if err != nil {
			return experiment.Configuration{}, err
		}
		return rec.Configuration, nil
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return experiment.Configuration{}, err
	}
	defer func() { _ = root.Close() }()
	body, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return experiment.Configuration{}, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	decoder.KnownFields(true)
	var config experiment.Configuration
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return config, errors.New("experiment file must contain one document")
	}
	return config, nil
}

func newFileRunCmd(replay bool) *cobra.Command {
	use, short := "run-file <experiment.yaml>", "run a versioned experiment file"
	if replay {
		use, short = "replay <run.json>", "repeat a recorded configuration after checking target identity"
	}
	cmd := &cobra.Command{
		Use: use, Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfiguration(args[0], replay)
			if err != nil {
				return err
			}
			return runConfiguration(cmd, config)
		},
	}
	cmd.Flags().Bool("plan", false, "check and describe without injecting")
	cmd.Flags().Duration(flagTTL, lease.DefaultTTL, ttlUsage)
	cmd.Flags().String(flagFailOn, FailOnAny, failOnUsage)
	cmd.Flags().String(flagRecord, "", recordUsage)
	cmd.Flags().String(flagOutput, outputText, outputUsage)
	cmd.Flags().String(flagJUnit, "", junitUsage)
	cmd.Flags().String(flagMetricsOut, "", metricsUsage)
	return cmd
}

func runConfiguration(
	cmd *cobra.Command,
	config experiment.Configuration,
) error {
	params, timing, err := config.Resolve(os.LookupEnv)
	if err != nil {
		return err
	}
	definition, err := experiment.Lookup(config.Experiment)
	if err != nil {
		return err
	}
	given := inputs{
		Project: config.Project, Supplied: params, Timing: timing,
		AbortAfter: config.AbortAfter, Expected: config.Target,
	}
	plan, _ := cmd.Flags().GetBool("plan")
	if plan {
		return runPlan(cmd.Context(), cmd.OutOrStdout(), definition, given)
	}
	raw, _ := cmd.Flags().GetString(flagFailOn)
	gate, err := ParseGate(raw)
	if err != nil {
		return err
	}
	shape, err := outputShape(cmd)
	if err != nil {
		return err
	}
	projections, err := projectionsOf(cmd)
	if err != nil {
		return err
	}
	ttl, _ := cmd.Flags().GetDuration(flagTTL)
	into, _ := cmd.Flags().GetString(flagRecord)
	return runExperiment(
		cmd.Context(), cmd.OutOrStdout(), definition, ttl, given, gate,
		Output{
			Shape: shape, Record: into, Projections: projections,
			Diagnostic: cmd.ErrOrStderr(),
		},
	)
}
