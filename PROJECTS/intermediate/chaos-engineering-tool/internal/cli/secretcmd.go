// ©AngelaMos | 2026
// secretcmd.go

package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/CarterPerez-dev/khaos/internal/dockerx"
	"github.com/CarterPerez-dev/khaos/internal/secretfile"
	"github.com/spf13/cobra"
)

const (
	secretMutateUse = "secret-mutate"

	secretMutateShort = "perform one secret-file mutation inside khaos's own helper container"

	secretMutateLong = `Not an operator command. khaos runs this inside a short-lived container of
its own, with the target's mount replicated and nothing else, to break a
secret file in place and to put it back afterwards.

It refuses to run anywhere else. The command writes to whatever path it is
given, so on a host it would be a way to truncate any file khaos can reach -
and khaos never writes host-global state.`

	flagSecretPath  = "path"
	flagSecretAside = "aside"
	flagMutateMode  = "mode"
	flagSecretBytes = "bytes"
	flagSecretBack  = "restore"

	usageSecretPath  = "the secret file's path inside the container"
	usageSecretAside = "where the original is kept, inside the same mount"
	usageSecretMode  = "which secret fault to perform"
	usageSecretBytes = "how many bytes of the secret survive a truncation"
	usageSecretBack  = "put the original back instead of breaking it"

	msgSecretApplied  = "broke %s as %s, original kept at %s"
	msgSecretRestored = "restored %s from %s"

	errNotInMutator = "%w: it only runs inside khaos's own mutator container, where %s is set. It writes to the path it is given, so khaos will not run it anywhere it could reach a host file"
)

var ErrNotInMutator = errors.New(
	"that command is khaos's own container entrypoint, not an operator command",
)

func newSecretMutateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    secretMutateUse,
		Short:  secretMutateShort,
		Long:   secretMutateLong,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Getenv(dockerx.MutatorNonce) == "" {
				return fmt.Errorf(
					errNotInMutator,
					ErrNotInMutator,
					dockerx.MutatorNonce,
				)
			}

			mutation, restore, err := secretMutation(cmd)
			if err != nil {
				return err
			}

			if restore {
				if err := mutation.Restore(); err != nil {
					return err
				}

				fmt.Fprintf(
					cmd.OutOrStdout(),
					msgSecretRestored+"\n",
					mutation.Path,
					mutation.Aside,
				)

				return nil
			}

			if err := mutation.Apply(); err != nil {
				return err
			}

			fmt.Fprintf(
				cmd.OutOrStdout(),
				msgSecretApplied+"\n",
				mutation.Path,
				mutation.Kind,
				mutation.Aside,
			)

			return nil
		},
	}

	cmd.Flags().String(flagSecretPath, "", usageSecretPath)
	cmd.Flags().String(flagSecretAside, "", usageSecretAside)
	cmd.Flags().String(flagMutateMode, "", usageSecretMode)
	cmd.Flags().Int(flagSecretBytes, 0, usageSecretBytes)
	cmd.Flags().Bool(flagSecretBack, false, usageSecretBack)
	cmd.Flags().Uint32(
		"original-mode", 0, "original permission bits captured before the fault",
	)
	cmd.Flags().Int64(
		"original-size", 0, "original size captured before the fault",
	)

	return cmd
}

func secretMutation(cmd *cobra.Command) (secretfile.Mutation, bool, error) {
	path, err := cmd.Flags().GetString(flagSecretPath)
	if err != nil {
		return secretfile.Mutation{}, false, err
	}

	aside, err := cmd.Flags().GetString(flagSecretAside)
	if err != nil {
		return secretfile.Mutation{}, false, err
	}

	mode, err := cmd.Flags().GetString(flagMutateMode)
	if err != nil {
		return secretfile.Mutation{}, false, err
	}

	bytes, err := cmd.Flags().GetInt(flagSecretBytes)
	if err != nil {
		return secretfile.Mutation{}, false, err
	}

	restore, err := cmd.Flags().GetBool(flagSecretBack)
	if err != nil {
		return secretfile.Mutation{}, false, err
	}

	if aside == "" {
		aside = secretfile.AsideFor(path)
	}

	mutation := secretfile.Mutation{
		Kind:  secretfile.Kind(mode),
		Path:  path,
		Aside: aside,
		Bytes: bytes,
	}
	if cmd.Flags().Changed("original-mode") {
		originalMode, err := cmd.Flags().GetUint32("original-mode")
		if err != nil {
			return secretfile.Mutation{}, false, err
		}
		mutation.OriginalMode = &originalMode
	}
	if cmd.Flags().Changed("original-size") {
		originalSize, err := cmd.Flags().GetInt64("original-size")
		if err != nil {
			return secretfile.Mutation{}, false, err
		}
		mutation.OriginalSize = &originalSize
	}

	return mutation, restore, mutation.Validate()
}
