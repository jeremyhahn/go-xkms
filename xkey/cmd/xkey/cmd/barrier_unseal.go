// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// barrierUnsealCmd unseals the barrier by prompting for the password.
var barrierUnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal the barrier",
	Long: `Unseal the barrier by providing the password used during initialization.

This loads the sealed root key blob from the data directory, decrypts it
using the matching sealing strategy, and derives the data encryption key
(DEK). All subsequent storage operations are transparently encrypted with
AES-256-GCM.

Examples:
  # Unseal the barrier
  xkey barrier unseal

  # Unseal with custom data directory
  xkey barrier unseal --data-dir /secure/xkey

  # Unseal from piped password (for automation)
  echo "mypassword" | xkey barrier unseal

  # Unseal the barrier with the credential the TPM releases under the
  # auto-unseal policy (see 'xkey tpm policy auto-unseal'); no password is
  # read, so this is safe for unattended startup scripts
  xkey barrier unseal --auto`,
	RunE: runBarrierUnseal,
}

func init() {
	barrierCmd.AddCommand(barrierUnsealCmd)

	barrierUnsealCmd.Flags().Bool("auto", false,
		"Unseal via the TPM auto-unseal policy only (see 'xkey tpm policy auto-unseal'); never prompts for a password")
}

func runBarrierUnseal(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()

	// Resolve data directory.
	dataDir, err := resolveBarrierDataDir()
	if err != nil {
		return err
	}

	// Check if barrier is initialized.
	if !barrierRootKeyExists(dataDir) {
		return &BarrierError{
			Operation: "check_initialized",
			Message:   "barrier not initialized, run 'xkey barrier init' first",
		}
	}

	if auto, _ := cmd.Flags().GetBool("auto"); auto {
		return runBarrierUnsealAuto(cmd, dataDir)
	}

	// Read password.
	password, err := readBarrierPassword(out, "Enter barrier password: ")
	if err != nil {
		return err
	}

	// Create barrier and unseal.
	barrier, closer, err := createBarrier(dataDir)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := barrier.Close(); cerr != nil {
			err = errors.Join(err, cerr)
		}
		if closer != nil {
			if cerr := closer.Close(); cerr != nil {
				err = errors.Join(err, cerr)
			}
		}
	}()

	// The CLI has already rejected an empty password above, and this []byte
	// conversion is a fresh copy this function owns and never reads again, so
	// NewCredentials (move + wipe) is used rather than CredentialsFor (copy).
	ctx := cmd.Context()
	creds, credErr := xkms.NewCredentials(ctx, []byte(password))
	if credErr != nil {
		return &BarrierError{
			Operation: "build_credentials",
			Err:       credErr,
		}
	}
	defer creds.Secret.Destroy()

	if err := barrier.Unseal(ctx, creds); err != nil {
		return &BarrierError{
			Operation: "unseal",
			Err:       err,
		}
	}

	strategy := strategyDisplayName(barrier.ActiveStrategy())
	_, _ = fmt.Fprintf(out, "Barrier unsealed successfully.\n")
	_, _ = fmt.Fprintf(out, "  Strategy: %s\n", strategy)

	return nil
}

// runBarrierUnsealAuto unseals the barrier with the credential the TPM
// releases under the auto-unseal policy (see 'xkey tpm policy auto-unseal')
// and nothing else: it never prompts for or reads a password, so it is safe
// to wire into unattended startup scripts. It runs the auto-unseal exactly
// once and reports the outcome; it does not fall back to a password.
func runBarrierUnsealAuto(cmd *cobra.Command, dataDir string) error {
	out := cmd.OutOrStdout()
	logger := slog.Default()

	strategy, err := readBarrierStrategy(dataDir)
	if err != nil {
		return &BarrierError{Operation: "read_strategy", Err: err}
	}

	home, err := xhome.Resolve()
	if err != nil {
		return &BarrierError{Operation: "resolve_home", Err: err}
	}

	barrierSvc := services.NewBarrierService(home.Root, logger)
	barrierSvc.SetDataDir(dataDir)

	// The returned TPM closer is intentionally left unclosed: this command
	// is a single short-lived process that exits right after reporting the
	// outcome below, and the OS reclaims the device handle at exit (see
	// unsealTPM2BarrierService in barrier_store.go for the same rationale).
	unsealed, _, err := tryBarrierPolicyAutoUnseal(context.Background(), logger, barrierSvc, dataDir, strategy, barrierTPMDevice, barrierTPMSimulator)
	if err != nil {
		return &BarrierError{Operation: "auto_unseal", Err: err}
	}
	if !unsealed {
		return &BarrierError{
			Operation: "auto_unseal",
			Message:   "no auto-unseal policy configured; run 'xkey tpm policy auto-unseal <name>' first",
		}
	}

	_, _ = fmt.Fprintln(out, "Barrier auto-unsealed through the TPM auto-unseal policy.")
	_, _ = fmt.Fprintf(out, "  Strategy: %s\n", strategyDisplayName(strategy))

	return nil
}
