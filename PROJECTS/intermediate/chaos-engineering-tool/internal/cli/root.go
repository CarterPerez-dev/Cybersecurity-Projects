// ©AngelaMos | 2026
// root.go

package cli

import (
	"fmt"

	"github.com/CarterPerez-dev/khaos/internal/banner"
	"github.com/CarterPerez-dev/khaos/internal/version"
	"github.com/spf13/cobra"
)

const (
	FlagNoColor = "no-color"

	rootShort = "inject security failures and measure whether controls fail closed"
	rootLong  = `khaos injects controlled security failures into a Docker-scoped target and
measures whether the target failed closed or failed open.

It probes with legitimate and invalid credentials before, during, and after
each fault, then reports the observed security behavior and recovery status.

Run khaos with no arguments in a terminal to open the interactive console.`

	versionShort = "print the khaos version"
	bannerShort  = "print the khaos banner"
	noColorUsage = "disable all color output"

	versionFormat = "%s %s\n"
)

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           version.Name,
		Short:         rootShort,
		Long:          rootLong,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().Bool(FlagNoColor, false, noColorUsage)
	root.AddCommand(
		newVersionCmd(),
		newBannerCmd(),
		newDoctorCmd(),
		newTargetsCmd(),
		newInjectCmd(),
		newRangeCmd(),
		newResolverCmd(),
		newSecretMutateCmd(),
		newServeResolverCmd(),
		newCatalogCmd(),
		newPlanCmd(),
		newRunCmd(),
		newRunsCmd(),
		newShowCmd(),
		newFileRunCmd(false),
		newFileRunCmd(true),
		newReclaimCmd(),
		newReapCmd(),
	)

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: versionShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(
				cmd.OutOrStdout(),
				versionFormat,
				version.Name,
				version.Version(),
			)
			return err
		},
	}
}

func newBannerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "banner",
		Short: bannerShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return banner.Write(cmd.OutOrStdout())
		},
	}
}
