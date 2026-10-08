// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
	"github.com/jeremyhahn/go-xkms/pkg/preseal"
)

// seal-pkcs11-pin and seal-vault-token subcommand error types.
var (
	// ErrSealSecretConfigRequired is returned when --config is not given:
	// the TPM and the pre-barrier store both come from the configuration
	// `xkmsd run` loads.
	ErrSealSecretConfigRequired = errors.New("seal secret: --config is required")

	// ErrSealSecretReadFailed is returned when standard input cannot be read.
	ErrSealSecretReadFailed = errors.New("seal secret: failed to read the secret from standard input")

	// ErrSealSecretEmpty is returned when standard input carries no secret.
	ErrSealSecretEmpty = errors.New("seal secret: the secret must not be empty")
)

// presealSecret is a node seal credential that an `xkmsd seal-*` verb seals
// into the pre-barrier secret store, so that `xkmsd run` can release it
// before any server or node exists.
type presealSecret struct {
	// verb is the subcommand name.
	verb string
	// key is the secret's name in the pre-barrier store.
	key string
	// label names the secret in messages.
	label string
	// strategy is the barrier.strategy whose boot releases the secret.
	strategy string
}

var (
	// pkcs11PINSecret is the PKCS#11 token's user PIN, released by the
	// pkcs11 node seal to log in to the token.
	pkcs11PINSecret = presealSecret{
		verb:     "seal-pkcs11-pin",
		key:      preseal.PKCS11PIN,
		label:    "PKCS#11 PIN",
		strategy: "pkcs11",
	}

	// vaultTokenSecret is the Vault token the vault node seal authenticates
	// to Transit with.
	vaultTokenSecret = presealSecret{
		verb:     "seal-vault-token",
		key:      preseal.VaultToken,
		label:    "Vault token",
		strategy: "vault",
	}
)

// sealSecretFlags holds a seal-* subcommand's flags.
type sealSecretFlags struct {
	configPath string
}

// run seals the secret read from standard input and returns the process
// exit code.
func (s presealSecret) run(args []string) int {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := s.command(args, os.Stdin, logger); err != nil {
		logger.Error("sealing the "+s.label+" failed", slog.Any("error", err))
		return 1
	}
	logger.Info(s.label+" sealed in the pre-barrier secret store", slog.String("secret", s.key))
	return 0
}

// command parses args, loads the configuration and seals the secret read
// from stdin.
func (s presealSecret) command(args []string, stdin io.Reader, logger *slog.Logger) error {
	flags, err := s.parseFlags(args)
	if err != nil {
		return err
	}
	if flags.configPath == "" {
		return ErrSealSecretConfigRequired
	}
	cfg, err := config.Load(flags.configPath)
	if err != nil {
		return &WrappedError{Sentinel: ErrConfigLoad, Err: err}
	}
	secret, err := readSecret(stdin)
	if err != nil {
		return err
	}
	defer clear(secret)
	return s.seal(cfg, logger, secret)
}

// seal seals secret into cfg's pre-barrier store, replacing any value sealed
// before.
func (s presealSecret) seal(cfg *config.Config, logger *slog.Logger, secret []byte) error {
	store, closeStore, err := embeddednode.OpenPreseal(cfg, logger)
	if err != nil {
		return err
	}
	return errors.Join(store.Put(context.Background(), s.key, secret), closeStore())
}

// readSecret reads a secret from r, without its trailing newline. There is
// no flag form: a secret in argv is world-readable through /proc for the
// life of the process.
func readSecret(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, &WrappedError{Sentinel: ErrSealSecretReadFailed, Err: err}
	}
	secret := []byte(strings.TrimRight(string(data), "\r\n"))
	clear(data)
	if len(secret) == 0 {
		return nil, ErrSealSecretEmpty
	}
	return secret, nil
}

// parseFlags creates and parses the subcommand's FlagSet.
func (s presealSecret) parseFlags(args []string) (*sealSecretFlags, error) {
	fs := flag.NewFlagSet(s.verb, flag.ContinueOnError)
	flags := &sealSecretFlags{}

	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage: xkmsd %s --config <path> < secret.txt\n", s.verb)
		_, _ = fmt.Fprintln(fs.Output(), "")
		_, _ = fmt.Fprintf(fs.Output(), "Seal the %s under the TPM's platform policy, so `xkmsd run`\n", s.label)
		_, _ = fmt.Fprintf(fs.Output(), "with barrier.strategy %s unseals the node unattended.\n", s.strategy)
		_, _ = fmt.Fprintf(fs.Output(), "The %s is read from standard input, never a flag.\n", s.label)
		_, _ = fmt.Fprintln(fs.Output(), "")
		_, _ = fmt.Fprintln(fs.Output(), "Flags:")
		fs.PrintDefaults()
	}

	fs.StringVar(&flags.configPath, "config", "", "Path to configuration file (required)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return flags, nil
}
