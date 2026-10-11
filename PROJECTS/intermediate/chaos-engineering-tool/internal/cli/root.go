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

Every other chaos tool asks whether the system stayed up. khaos asks which way
it broke, by probing with a legitimate credential and an invalid one at the
same time and comparing how the two move.

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
		newCatalogCmd(),
		newPlanCmd(),
		newRunCmd(),
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
