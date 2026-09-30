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
	"io"
	"strings"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// vaultFactorPassphrase is the wire name of the passphrase vault factor.
const vaultFactorPassphrase = "passphrase"

// Personal password vault command errors.
var (
	// ErrPasswordMissingPassphrase indicates no vault passphrase was supplied.
	ErrPasswordMissingPassphrase = errors.New("password: a vault passphrase is required " +
		"(--passphrase-stdin or XKEY_VAULT_PASSPHRASE)")

	// ErrPasswordPassphraseStdinEmpty indicates --passphrase-stdin was given
	// but standard input carried no passphrase.
	ErrPasswordPassphraseStdinEmpty = errors.New("password: --passphrase-stdin was given but standard input carried no passphrase")

	// ErrPasswordVaultStdinRead indicates standard input could not be read
	// for a vault secret.
	ErrPasswordVaultStdinRead = errors.New("password: failed to read the vault secret from standard input")

	// ErrPasswordMissingRecoveryCode indicates no recovery code was supplied.
	ErrPasswordMissingRecoveryCode = errors.New("password: a recovery code is required " +
		"(--recovery-code-stdin or XKEY_VAULT_RECOVERY_CODE)")

	// ErrPasswordRecoveryCodeStdinEmpty indicates --recovery-code-stdin was
	// given but standard input carried no recovery code.
	ErrPasswordRecoveryCodeStdinEmpty = errors.New("password: --recovery-code-stdin was given but standard input carried no recovery code")

	// ErrPasswordVaultSingleStdin indicates both vault secrets were asked to
	// come from standard input, which can carry only one.
	ErrPasswordVaultSingleStdin = errors.New("password: only one of --recovery-code-stdin and --passphrase-stdin may be given; " +
		"supply the other through its environment variable")

	// ErrPasswordMissingFactorID indicates a vault verb that acts on one
	// factor was not given --factor-id.
	ErrPasswordMissingFactorID = errors.New("password: --factor-id is required (see 'xkey password vault status')")

	// ErrPasswordVaultStatusFailed indicates the vault status could not be read.
	ErrPasswordVaultStatusFailed = errors.New("password: vault status operation failed")

	// ErrPasswordVaultEnrollFailed indicates a vault factor could not be enrolled.
	ErrPasswordVaultEnrollFailed = errors.New("password: vault enroll operation failed")

	// ErrPasswordVaultRotateFailed indicates a vault factor could not be rotated.
	ErrPasswordVaultRotateFailed = errors.New("password: vault rotate operation failed")

	// ErrPasswordVaultRemoveFailed indicates a vault factor could not be removed.
	ErrPasswordVaultRemoveFailed = errors.New("password: vault remove operation failed")

	// ErrPasswordVaultRecoverFailed indicates the vault could not be recovered.
	ErrPasswordVaultRecoverFailed = errors.New("password: vault recover operation failed")
)

// vaultPassphraseSource is how a vault passphrase enters the CLI: standard
// input or the environment, never a value flag (go-xkms#1209).
var vaultPassphraseSource = pinSource{
	label:      "vault passphrase",
	stdinFlag:  "passphrase-stdin",
	envVar:     "XKEY_VAULT_PASSPHRASE",
	stdinEmpty: ErrPasswordPassphraseStdinEmpty,
	stdinRead:  ErrPasswordVaultStdinRead,
}

// vaultRecoveryCodeSource is how the one-time recovery code enters the CLI.
var vaultRecoveryCodeSource = pinSource{
	label:      "recovery code",
	stdinFlag:  "recovery-code-stdin",
	envVar:     "XKEY_VAULT_RECOVERY_CODE",
	stdinEmpty: ErrPasswordRecoveryCodeStdinEmpty,
	stdinRead:  ErrPasswordVaultStdinRead,
}

// vaultPassphraseUsage documents the passphrase inputs in command help.
const vaultPassphraseUsage = `The vault passphrase may be supplied two ways, in precedence order:

  --passphrase-stdin     read it from standard input (preferred)
  XKEY_VAULT_PASSPHRASE  environment variable

There is no "--passphrase" value flag: a value on the command line is visible
to every other process on the host via 'ps'.`

// passwordVaultCmd groups the personal password vault verbs.
var passwordVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage your personal password vault on an xkmsd server",
	Long: `Manage the factors that unlock your personal password entries on an
xkmsd server (requires --xkmsd-url).

Your personal entries are sealed with a key only your own factors unwrap: a
passphrase you choose. The first enrollment initializes the vault, opens your
session, and prints a one-time recovery code -- store it somewhere safe, it
is shown exactly once and is the only way back in if you lose every factor.
Recovering with it enrolls a new factor and prints a new code.

Subcommands:
  status   Show whether the vault is initialized and unlocked, and its factors
  enroll   Enroll a passphrase (the first enrollment initializes the vault)
  rotate   Replace the passphrase of an enrolled factor
  remove   Remove an enrolled factor
  recover  Enroll a new passphrase with the one-time recovery code`,
}

// passwordVaultStatusCmd shows the caller's vault status.
var passwordVaultStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show your personal vault status and factors",
	Long: `Show whether your personal vault is initialized and unlocked, and list
its enrolled factors (never their secrets).

Example:
  xkey password vault status --xkmsd-url https://kms.example.com`,
	RunE: runPasswordVaultStatus,
}

// passwordVaultEnrollCmd enrolls a passphrase factor.
var passwordVaultEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a passphrase on your personal vault",
	Long: `Enroll a passphrase on your personal vault.

The first enrollment initializes the vault, opens your session, and prints the
one-time recovery code. Later enrollments add a factor and need your session
open ('xkey password unlock').

` + vaultPassphraseUsage + `

Example:
  xkey password vault enroll --passphrase-stdin --label laptop < passphrase.txt`,
	RunE: runPasswordVaultEnroll,
}

// passwordVaultRotateCmd replaces the passphrase of an enrolled factor.
var passwordVaultRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace the passphrase of an enrolled factor",
	Long: `Replace the passphrase of the factor named by --factor-id. Your session
must be open ('xkey password unlock'). The rotated factor gets a new ID and
keeps its label unless --label names a new one.

` + vaultPassphraseUsage + `

Example:
  xkey password vault rotate --factor-id 3b9e... --passphrase-stdin < new.txt`,
	RunE: runPasswordVaultRotate,
}

// passwordVaultRemoveCmd removes an enrolled factor.
var passwordVaultRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove an enrolled factor",
	Long: `Remove the factor named by --factor-id. Your session must be open, and
the last passphrase or passkey cannot be removed.

Example:
  xkey password vault remove --factor-id 3b9e...`,
	RunE: runPasswordVaultRemove,
}

// passwordVaultRecoverCmd enrolls a new passphrase with the recovery code.
var passwordVaultRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Enroll a new passphrase with your one-time recovery code",
	Long: `Use your one-time recovery code to enroll a new passphrase. This opens
your session and prints a NEW recovery code; the old one stops working.

The recovery code comes from --recovery-code-stdin or XKEY_VAULT_RECOVERY_CODE;
the new passphrase from --passphrase-stdin or XKEY_VAULT_PASSPHRASE. Standard
input carries only one of them.

Example:
  XKEY_VAULT_PASSPHRASE=... xkey password vault recover --recovery-code-stdin < code.txt`,
	RunE: runPasswordVaultRecover,
}

// resolveVaultSecret resolves one vault secret from its source, failing with
// missing when neither stdin nor the environment supplied it. The caller
// owns the returned bytes and must wipe them.
func resolveVaultSecret(cmd *cobra.Command, source pinSource, missing error) ([]byte, error) {
	secret, err := source.resolveBytes(cmd)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, missing
	}
	return secret, nil
}

// vaultPassphraseCredential builds the passphrase vault credential.
func vaultPassphraseCredential(passphrase []byte, label string) transport.PasswordVaultCredential {
	return transport.PasswordVaultCredential{
		Factor:     vaultFactorPassphrase,
		Passphrase: string(passphrase),
		Label:      label,
	}
}

// withPasswordStore connects to the xkmsd password service, runs fn, and
// closes the connection, joining a close failure into the result.
func withPasswordStore(fn func(ctx context.Context, client PasswordStoreClientService) error) (err error) {
	client, err := connectPasswordStore()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	return fn(context.Background(), client)
}

// runPasswordVaultStatus executes the vault status command.
func runPasswordVaultStatus(cmd *cobra.Command, args []string) error {
	return withPasswordStore(func(ctx context.Context, client PasswordStoreClientService) error {
		resp, err := client.PasswordVaultStatus(ctx)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrPasswordVaultStatusFailed, Cause: err}
		}
		return writeVaultStatus(cmd.OutOrStdout(), resp)
	})
}

// runPasswordVaultEnroll executes the vault enroll command.
func runPasswordVaultEnroll(cmd *cobra.Command, args []string) error {
	label, err := cmd.Flags().GetString("label")
	if err != nil {
		return err
	}
	passphrase, err := resolveVaultSecret(cmd, vaultPassphraseSource, ErrPasswordMissingPassphrase)
	if err != nil {
		return err
	}
	defer enclave.Wipe(passphrase)

	return withPasswordStore(func(ctx context.Context, client PasswordStoreClientService) error {
		resp, err := client.PasswordVaultEnroll(ctx, &transport.PasswordVaultEnrollRequest{
			PasswordVaultCredential: vaultPassphraseCredential(passphrase, label),
		})
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrPasswordVaultEnrollFailed, Cause: err}
		}
		return writeVaultEnrollResult(cmd.OutOrStdout(), "Vault factor enrolled", resp)
	})
}

// runPasswordVaultRotate executes the vault rotate command.
func runPasswordVaultRotate(cmd *cobra.Command, args []string) error {
	factorID, err := cmd.Flags().GetString("factor-id")
	if err != nil {
		return err
	}
	if factorID == "" {
		return ErrPasswordMissingFactorID
	}
	label, err := cmd.Flags().GetString("label")
	if err != nil {
		return err
	}
	passphrase, err := resolveVaultSecret(cmd, vaultPassphraseSource, ErrPasswordMissingPassphrase)
	if err != nil {
		return err
	}
	defer enclave.Wipe(passphrase)

	return withPasswordStore(func(ctx context.Context, client PasswordStoreClientService) error {
		if label == "" {
			current, err := vaultFactorLabel(ctx, client, factorID)
			if err != nil {
				return &SentinelCauseError{Sentinel: ErrPasswordVaultRotateFailed, Cause: err}
			}
			label = current
		}
		resp, err := client.PasswordVaultRotate(ctx, &transport.PasswordVaultRotateRequest{
			FactorID:                factorID,
			PasswordVaultCredential: vaultPassphraseCredential(passphrase, label),
		})
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrPasswordVaultRotateFailed, Cause: err}
		}
		return writeVaultEnrollResult(cmd.OutOrStdout(), "Vault factor rotated", resp)
	})
}

// vaultFactorLabel returns the label of factor id, so a rotation that names
// no new label keeps the factor's current one instead of clearing it. An
// unknown id yields an empty label; the rotation itself then reports it.
func vaultFactorLabel(ctx context.Context, client PasswordStoreClientService, id string) (string, error) {
	status, err := client.PasswordVaultStatus(ctx)
	if err != nil {
		return "", err
	}
	for _, f := range status.Factors {
		if f.ID == id {
			return f.Label, nil
		}
	}
	return "", nil
}

// runPasswordVaultRemove executes the vault remove command.
func runPasswordVaultRemove(cmd *cobra.Command, args []string) error {
	factorID, err := cmd.Flags().GetString("factor-id")
	if err != nil {
		return err
	}
	if factorID == "" {
		return ErrPasswordMissingFactorID
	}

	return withPasswordStore(func(ctx context.Context, client PasswordStoreClientService) error {
		req := &transport.PasswordVaultRemoveFactorRequest{FactorID: factorID}
		if err := client.PasswordVaultRemoveFactor(ctx, req); err != nil {
			return &SentinelCauseError{Sentinel: ErrPasswordVaultRemoveFailed, Cause: err}
		}
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Vault factor %s removed.\n", factorID)
		return err
	})
}

// runPasswordVaultRecover executes the vault recover command.
func runPasswordVaultRecover(cmd *cobra.Command, args []string) error {
	label, err := cmd.Flags().GetString("label")
	if err != nil {
		return err
	}
	codeFromStdin, err := cmd.Flags().GetBool(vaultRecoveryCodeSource.stdinFlag)
	if err != nil {
		return err
	}
	passphraseFromStdin, err := cmd.Flags().GetBool(vaultPassphraseSource.stdinFlag)
	if err != nil {
		return err
	}
	if codeFromStdin && passphraseFromStdin {
		return ErrPasswordVaultSingleStdin
	}

	code, err := resolveVaultSecret(cmd, vaultRecoveryCodeSource, ErrPasswordMissingRecoveryCode)
	if err != nil {
		return err
	}
	defer enclave.Wipe(code)
	passphrase, err := resolveVaultSecret(cmd, vaultPassphraseSource, ErrPasswordMissingPassphrase)
	if err != nil {
		return err
	}
	defer enclave.Wipe(passphrase)

	return withPasswordStore(func(ctx context.Context, client PasswordStoreClientService) error {
		resp, err := client.PasswordVaultRecover(ctx, &transport.PasswordVaultRecoverRequest{
			RecoveryCode:            string(code),
			PasswordVaultCredential: vaultPassphraseCredential(passphrase, label),
		})
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrPasswordVaultRecoverFailed, Cause: err}
		}
		return writeVaultEnrollResult(cmd.OutOrStdout(), "Vault recovered; new factor enrolled", resp)
	})
}

// writeVaultStatus renders the vault status.
func writeVaultStatus(out io.Writer, resp *transport.PasswordVaultStatusResponse) error {
	var b strings.Builder
	b.WriteString("Personal Vault:\n\n")
	fmt.Fprintf(&b, "  Initialized:  %s\n", boolToYesNo(resp.Initialized))
	fmt.Fprintf(&b, "  Unlocked:     %s\n", boolToYesNo(resp.Unlocked))
	if len(resp.Factors) == 0 {
		b.WriteString("  Factors:      none (enroll one with 'xkey password vault enroll')\n")
	} else {
		b.WriteString("  Factors:\n")
		fmt.Fprintf(&b, "    %-36s %-10s %-20s %s\n", "ID", "FACTOR", "LABEL", "CREATED")
		for _, f := range resp.Factors {
			fmt.Fprintf(&b, "    %-36s %-10s %-20s %s\n", f.ID, f.Factor, f.Label, f.CreatedAt)
		}
	}
	_, err := io.WriteString(out, b.String())
	return err
}

// writeVaultEnrollResult renders an enrolled factor and, when the server
// issued one, the recovery code with the warning that it is shown once.
func writeVaultEnrollResult(out io.Writer, heading string, resp *transport.PasswordVaultEnrollResponse) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", heading)
	fmt.Fprintf(&b, "  ID:       %s\n", resp.Factor.ID)
	fmt.Fprintf(&b, "  Factor:   %s\n", resp.Factor.Factor)
	if resp.Factor.Label != "" {
		fmt.Fprintf(&b, "  Label:    %s\n", resp.Factor.Label)
	}
	fmt.Fprintf(&b, "  Created:  %s\n", resp.Factor.CreatedAt)
	if resp.RecoveryCode != "" {
		b.WriteString("\n================================ RECOVERY CODE ================================\n")
		fmt.Fprintf(&b, "  %s\n\n", resp.RecoveryCode)
		b.WriteString("  Store this now; it will not be shown again. It is the only way back into\n")
		b.WriteString("  your personal vault if you lose every passphrase and passkey.\n")
		b.WriteString("===============================================================================\n")
	}
	_, err := io.WriteString(out, b.String())
	return err
}

func init() {
	PasswordCmd.AddCommand(passwordVaultCmd)
	passwordVaultCmd.AddCommand(passwordVaultStatusCmd)
	passwordVaultCmd.AddCommand(passwordVaultEnrollCmd)
	passwordVaultCmd.AddCommand(passwordVaultRotateCmd)
	passwordVaultCmd.AddCommand(passwordVaultRemoveCmd)
	passwordVaultCmd.AddCommand(passwordVaultRecoverCmd)

	vaultPassphraseSource.addFlags(passwordVaultEnrollCmd)
	passwordVaultEnrollCmd.Flags().String("label", "", "Label naming the factor (e.g. the device it is used on)")

	passwordVaultRotateCmd.Flags().String("factor-id", "", "ID of the factor to rotate (see 'xkey password vault status')")
	vaultPassphraseSource.addFlags(passwordVaultRotateCmd)
	passwordVaultRotateCmd.Flags().String("label", "", "New label for the factor (default: keep the current one)")

	passwordVaultRemoveCmd.Flags().String("factor-id", "", "ID of the factor to remove (see 'xkey password vault status')")

	vaultRecoveryCodeSource.addFlags(passwordVaultRecoverCmd)
	vaultPassphraseSource.addFlags(passwordVaultRecoverCmd)
	passwordVaultRecoverCmd.Flags().String("label", "", "Label naming the new factor")
}
