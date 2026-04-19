/*
©AngelaMos | 2026
keygen.go

Generate and persist an Ed25519 SSH host key

Writes a PEM-encoded private key to disk for use by the SSH
honeypot. The key is used to present a stable host fingerprint
across restarts so that returning attackers see the same server
identity.
*/

package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var outputPath string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an SSH host key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateHostKey(outputPath)
		},
	}

	cmd.Flags().StringVarP(
		&outputPath,
		"output", "o",
		"data/hostkey_ed25519",
		"Output path for the private key",
	)

	return cmd
}

func generateHostKey(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating key directory: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	f, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600,
	)
	if err != nil {
		return fmt.Errorf("creating key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	fmt.Printf("  %s Host key written to %s\n", "✓", path)

	return nil
}
