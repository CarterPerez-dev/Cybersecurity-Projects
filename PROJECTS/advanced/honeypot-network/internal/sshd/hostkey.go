/*
©AngelaMos | 2026
hostkey.go

SSH host key generation and persistence

Generates Ed25519 keys and persists them to disk so that the
honeypot presents a stable fingerprint across restarts. Returning
attackers see the same server identity, preventing fingerprinting
based on key rotation.
*/

package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func LoadOrGenerateHostKey(
	path string,
) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, parseErr := ssh.ParsePrivateKey(data)
		if parseErr != nil {
			return nil, fmt.Errorf(
				"parsing host key: %w", parseErr,
			)
		}
		return signer, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading host key: %w", err)
	}

	return generateAndSave(path)
}

func generateAndSave(path string) (ssh.Signer, error) {
	if err := os.MkdirAll(
		filepath.Dir(path), 0o700,
	); err != nil {
		return nil, fmt.Errorf(
			"creating key directory: %w", err,
		)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshaling key: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}

	f, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("creating key file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return nil, fmt.Errorf("writing key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	return signer, nil
}
