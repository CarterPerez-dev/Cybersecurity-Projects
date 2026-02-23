// ©AngelaMos | 2026
// init.go

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/portia/internal/config"
	"github.com/CarterPerez-dev/portia/internal/ui"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a default .portia.toml config file",
	RunE:  runInit,
}

var pyprojectCmd = &cobra.Command{
	Use:   "pyproject",
	Short: "Create a pyproject.toml with [tool.portia] configuration",
	RunE:  runPyproject,
}

func runInit(_ *cobra.Command, _ []string) error {
	if _, err := os.Stat(config.DefaultConfigFile); err == nil {
		fmt.Fprintf(os.Stderr, "%s %s already exists\n",
			ui.Warning, config.DefaultConfigFile)
		return nil
	}

	if err := os.WriteFile( //nolint:gosec
		config.DefaultConfigFile,
		[]byte(config.DefaultTemplate()),
		0o644,
	); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Fprintf(os.Stdout, "%s Created %s\n", //nolint:errcheck
		ui.Check, ui.CyanBold(config.DefaultConfigFile))
	return nil
}

func runPyproject(_ *cobra.Command, _ []string) error {
	if _, err := os.Stat("pyproject.toml"); err == nil {
		return fmt.Errorf("pyproject.toml already exists")
	}

	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	name := filepath.Base(dir)
	content := config.PyprojectTemplate(name)

	if err := os.WriteFile( //nolint:gosec
		"pyproject.toml",
		[]byte(content),
		0o644,
	); err != nil {
		return fmt.Errorf("write pyproject.toml: %w", err)
	}

	fmt.Fprintf(os.Stdout, "\n  %s %s\n\n", //nolint:errcheck
		ui.HiGreen(ui.Check),
		ui.HiGreen("Created pyproject.toml with [tool.portia] configuration"))
	return nil
}
