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

package main

import (
	"context"
	"os"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/spf13/cobra"
)

// vaultFactorPassphrase is the wire name of the passphrase vault factor.
const vaultFactorPassphrase = "passphrase"

// passwordVaultCmd groups the personal password vault verbs.
var passwordVaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage your personal password vault",
	Long: `Manage the factors that unlock your personal password entries.

Your personal entries are sealed with a key only your own factors unwrap:
a passphrase you choose. The first enrollment initializes the vault, opens
your session, and prints a one-time recovery code -- store it somewhere
safe, it is shown exactly once and is the only way back in if you lose
every factor. Recovering with it enrolls a new factor and prints a new code.

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
  xkmsctl password vault status`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)
		passwordVaultStatus(cfg, printer)
	},
}

// passwordVaultEnrollCmd enrolls a passphrase factor.
var passwordVaultEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll a passphrase on your personal vault",
	Long: `Enroll a passphrase on your personal vault.

The first enrollment initializes the vault, opens your session, and prints
the one-time recovery code. Later enrollments add a factor and need your
session open ("password unlock").

The passphrase is taken from --passphrase, from stdin when --passphrase is
"-", or from an interactive no-echo prompt (entered twice) when omitted.

Examples:
  xkmsctl password vault enroll --label laptop
  printf '%s' "$PASSPHRASE" | xkmsctl password vault enroll --passphrase -`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		passphraseFlag := fr.String("passphrase")
		label := fr.String("label")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		passphrase, err := resolveNewVaultPassphrase(passphraseFlag)
		if err != nil {
			handleError(err)
			return
		}

		passwordVaultEnroll(cfg, printer, &client.PasswordVaultEnrollRequest{
			PasswordVaultCredential: vaultPassphraseCredential(passphrase, label),
		})
	},
}

// passwordVaultRotateCmd replaces the passphrase of an enrolled factor.
var passwordVaultRotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Replace the passphrase of an enrolled factor",
	Long: `Replace the passphrase of the factor named by --factor-id. Your
session must be open ("password unlock"). The rotated factor gets a new ID
and keeps its label unless --label names a new one.

The new passphrase is taken from --passphrase, from stdin when --passphrase
is "-", or from an interactive no-echo prompt (entered twice) when omitted.

Example:
  xkmsctl password vault rotate --factor-id 3b9e...`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		factorID := fr.String("factor-id")
		passphraseFlag := fr.String("passphrase")
		label := fr.String("label")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if factorID == "" {
			handleError(ErrVaultFactorIDRequired)
			return
		}
		passphrase, err := resolveNewVaultPassphrase(passphraseFlag)
		if err != nil {
			handleError(err)
			return
		}

		passwordVaultRotate(cfg, printer, &client.PasswordVaultRotateRequest{
			FactorID:                factorID,
			PasswordVaultCredential: vaultPassphraseCredential(passphrase, label),
		})
	},
}

// passwordVaultRemoveCmd removes an enrolled factor.
var passwordVaultRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove an enrolled factor",
	Long: `Remove the factor named by --factor-id. Your session must be open,
and the last passphrase or passkey cannot be removed.

Example:
  xkmsctl password vault remove --factor-id 3b9e...`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		factorID := fr.String("factor-id")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if factorID == "" {
			handleError(ErrVaultFactorIDRequired)
			return
		}

		passwordVaultRemoveFactor(cfg, printer, factorID)
	},
}

// passwordVaultRecoverCmd enrolls a new passphrase with the recovery code.
var passwordVaultRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Enroll a new passphrase with your one-time recovery code",
	Long: `Use your one-time recovery code to enroll a new passphrase. This opens
your session and prints a NEW recovery code; the old one stops working.

The recovery code and the new passphrase are each taken from their flag,
from stdin when the flag is "-" (only one of them may be "-"), or from an
interactive no-echo prompt when omitted.

Example:
  xkmsctl password vault recover --label desktop`,
	Run: func(cmd *cobra.Command, args []string) {
		cfg := getConfig()
		printer := NewPrinter(cfg.OutputFormat, os.Stdout)

		fr := newFlagReader(cmd)
		codeFlag := fr.String("recovery-code")
		passphraseFlag := fr.String("passphrase")
		label := fr.String("label")
		if err := fr.Err(); err != nil {
			handleError(err)
			return
		}
		if codeFlag == "-" && passphraseFlag == "-" {
			handleError(ErrVaultSingleStdin)
			return
		}
		code, err := resolveSecret(codeFlag, "Recovery code")
		if err != nil {
			handleError(err)
			return
		}
		if code == "" {
			handleError(ErrVaultRecoveryCodeRequired)
			return
		}
		passphrase, err := resolveNewVaultPassphrase(passphraseFlag)
		if err != nil {
			handleError(err)
			return
		}

		passwordVaultRecover(cfg, printer, &client.PasswordVaultRecoverRequest{
			RecoveryCode:            code,
			PasswordVaultCredential: vaultPassphraseCredential(passphrase, label),
		})
	},
}

// vaultPassphraseCredential builds the passphrase vault credential.
func vaultPassphraseCredential(passphrase, label string) client.PasswordVaultCredential {
	return client.PasswordVaultCredential{
		Factor:     vaultFactorPassphrase,
		Passphrase: passphrase,
		Label:      label,
	}
}

// resolveVaultPassphrase resolves the passphrase that unlocks an existing
// factor: the flag value, stdin for "-", or one no-echo prompt.
func resolveVaultPassphrase(value string) (string, error) {
	passphrase, err := resolveSecret(value, "Vault passphrase")
	if err != nil {
		return "", err
	}
	if passphrase == "" {
		return "", ErrVaultPassphraseRequired
	}
	return passphrase, nil
}

// resolveNewVaultPassphrase resolves a passphrase being set. When it is
// prompted for on a terminal it is entered twice, so a typo cannot lock the
// user out of a factor they never actually chose.
func resolveNewVaultPassphrase(value string) (string, error) {
	passphrase, err := resolveVaultPassphrase(value)
	if err != nil {
		return "", err
	}
	if value != "" || !isTerminalFn(secretStdinFd()) {
		return passphrase, nil
	}
	confirmation, err := resolveSecret("", "Confirm vault passphrase")
	if err != nil {
		return "", err
	}
	if confirmation != passphrase {
		return "", ErrVaultPassphraseMismatch
	}
	return passphrase, nil
}

// passwordVaultStatus prints the caller's vault status.
func passwordVaultStatus(cfg *Config, printer *Printer) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.PasswordVaultStatus(context.Background())
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrVaultStatusFailed, Err: err})
		return
	}

	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("Personal Vault:\n")
		printer.printf("  Initialized: %t\n", resp.Initialized)
		printer.printf("  Unlocked:    %t\n", resp.Unlocked)
		if len(resp.Factors) == 0 {
			printer.println("  Factors:     none (enroll one with \"password vault enroll\")")
			break
		}
		printer.println("  Factors:")
		printer.printf("    %-36s %-10s %-20s %s\n", "ID", "FACTOR", "LABEL", "CREATED")
		for _, f := range resp.Factors {
			printer.printf("    %-36s %-10s %-20s %s\n",
				truncateString(f.ID, 36), f.Factor, truncateString(f.Label, 20), f.CreatedAt)
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

// passwordVaultEnroll enrolls a factor and prints it, plus the recovery code
// when this was the vault's first enrollment.
func passwordVaultEnroll(cfg *Config, printer *Printer, req *client.PasswordVaultEnrollRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.PasswordVaultEnroll(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrVaultEnrollFailed, Err: err})
		return
	}
	printVaultEnrollResult(printer, "Vault factor enrolled", resp)
}

// passwordVaultRotate re-wraps the vault key under a factor's new secret.
func passwordVaultRotate(cfg *Config, printer *Printer, req *client.PasswordVaultRotateRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	if req.Label == "" {
		label, err := vaultFactorLabel(cl, req.FactorID)
		if err != nil {
			handleError(&WrappedError{Sentinel: ErrVaultRotateFailed, Err: err})
			return
		}
		req.Label = label
	}

	resp, err := cl.PasswordVaultRotate(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrVaultRotateFailed, Err: err})
		return
	}
	printVaultEnrollResult(printer, "Vault factor rotated", resp)
}

// vaultFactorLabel returns the label of factor id, so a rotation that names
// no new label keeps the factor's current one instead of clearing it. An
// unknown id yields an empty label; the rotation itself then reports it.
func vaultFactorLabel(cl client.Client, id string) (string, error) {
	status, err := cl.PasswordVaultStatus(context.Background())
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

// passwordVaultRemoveFactor removes one of the caller's factors.
func passwordVaultRemoveFactor(cfg *Config, printer *Printer, factorID string) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	req := &client.PasswordVaultRemoveFactorRequest{FactorID: factorID}
	if err := cl.PasswordVaultRemoveFactor(context.Background(), req); err != nil {
		handleError(&WrappedError{Sentinel: ErrVaultRemoveFactorFailed, Err: err})
		return
	}
	if err := printer.PrintSuccess("Vault factor " + factorID + " removed"); err != nil {
		handleError(err)
	}
}

// passwordVaultRecover enrolls a new factor with the recovery code and
// prints the replacement recovery code.
func passwordVaultRecover(cfg *Config, printer *Printer, req *client.PasswordVaultRecoverRequest) {
	cl, cleanup, err := createPasswordClient(cfg)
	if err != nil {
		handleError(err)
		return
	}
	defer cleanup()

	resp, err := cl.PasswordVaultRecover(context.Background(), req)
	if err != nil {
		handleError(&WrappedError{Sentinel: ErrVaultRecoverFailed, Err: err})
		return
	}
	printVaultEnrollResult(printer, "Vault recovered; new factor enrolled", resp)
}

// printVaultEnrollResult prints an enrolled factor and, when the server
// issued one, the recovery code with the warning that it is shown once.
func printVaultEnrollResult(printer *Printer, heading string, resp *client.PasswordVaultEnrollResponse) {
	switch printer.format {
	case OutputFormatJSON:
		if err := printer.PrintJSON(resp); err != nil {
			handleError(err)
		}
	case OutputFormatTable, OutputFormatText:
		printer.printf("%s:\n", heading)
		printer.printf("  ID:      %s\n", resp.Factor.ID)
		printer.printf("  Factor:  %s\n", resp.Factor.Factor)
		if resp.Factor.Label != "" {
			printer.printf("  Label:   %s\n", resp.Factor.Label)
		}
		printer.printf("  Created: %s\n", resp.Factor.CreatedAt)
		if resp.RecoveryCode != "" {
			printer.println("")
			printer.println("================================ RECOVERY CODE ================================")
			printer.printf("  %s\n", resp.RecoveryCode)
			printer.println("")
			printer.println("  Store this now; it will not be shown again. It is the only way back into")
			printer.println("  your personal vault if you lose every passphrase and passkey.")
			printer.println("===============================================================================")
		}
	}
	if err := printer.Err(); err != nil {
		handleError(err)
	}
}

func init() {
	passwordVaultEnrollCmd.Flags().String("passphrase", "", "passphrase to enroll ('-' reads stdin; prompted twice when omitted)")
	passwordVaultEnrollCmd.Flags().String("label", "", "label naming the factor (e.g. the device it is used on)")

	passwordVaultRotateCmd.Flags().String("factor-id", "", "ID of the factor to rotate (see \"password vault status\")")
	passwordVaultRotateCmd.Flags().String("passphrase", "", "new passphrase ('-' reads stdin; prompted twice when omitted)")
	passwordVaultRotateCmd.Flags().String("label", "", "new label for the factor")

	passwordVaultRemoveCmd.Flags().String("factor-id", "", "ID of the factor to remove (see \"password vault status\")")

	passwordVaultRecoverCmd.Flags().String("recovery-code", "", "one-time recovery code ('-' reads stdin; prompted when omitted)")
	passwordVaultRecoverCmd.Flags().String("passphrase", "", "new passphrase ('-' reads stdin; prompted twice when omitted)")
	passwordVaultRecoverCmd.Flags().String("label", "", "label naming the new factor")

	passwordVaultCmd.AddCommand(passwordVaultStatusCmd)
	passwordVaultCmd.AddCommand(passwordVaultEnrollCmd)
	passwordVaultCmd.AddCommand(passwordVaultRotateCmd)
	passwordVaultCmd.AddCommand(passwordVaultRemoveCmd)
	passwordVaultCmd.AddCommand(passwordVaultRecoverCmd)
	passwordCmd.AddCommand(passwordVaultCmd)
}
