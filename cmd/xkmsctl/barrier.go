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

// Package main provides Barrier Management CLI commands for xkmsctl.
//
// The canonical barrier verb tree mirrors qrdbctl / quicbaas / platformctl 1:1
// so operators have a single, consistent CLI surface across the entire
// stack:
//
//	barrier status                                        (read-only)
//	barrier init           --barrier-strategy <none|passphrase|shamir>
//	                       [--passphrase <passphrase>]       (required if strategy != none, rejected if = none)
//	                       [--so-pin <pin>]              (rejected when --barrier-strategy=none)
//	                       [--user-pin <pin>]            (requires --so-pin)
//	barrier init-shamir    --passphrase <passphrase>
//	                       --threshold N --total M
//	                       [--so-pin] [--user-pin]
//	barrier unseal         --passphrase <passphrase>         (passphrase / single-secret only)
//	barrier unseal-shares  --share <s> [--share <s> ...] | --shares-file <path>   ('-' = stdin)
//	barrier seal           [--so-pin <pin>] [-y|--assume-yes]
//	barrier rekey          --threshold N --total M       (xkms wire is Shamir-only)
//	                       [--so-pin <pin>]              (no secret on the wire)
//	barrier recovery generate  --threshold N --total M [--so-pin <pin>]
//	barrier recovery recover   --share <s> [--share <s> ...]
//
// xkms's BarrierService wire types do not carry SO/User PIN fields. To
// preserve UX parity at the CLI flag level while leaving the underlying
// wire untouched, the CLI dispatches to xkms's separate PIN RPCs
// (SetSOPIN, SetUserPIN, VerifySOPIN) before/after the barrier RPC as
// appropriate.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/spf13/cobra"
)

// =============================================================================
// Canonical barrier-strategy set (CLI-level concept)
// =============================================================================

// barrierStrategyInit enumerates the strategies accepted by `barrier
// init`. Map lookup is O(1); kept in lock-step with qrdbctl / quicbaas.
var barrierStrategyInit = map[string]struct{}{
	"none":       {},
	"passphrase": {},
	"shamir":     {},
}

// =============================================================================
// Command-level flag state
// =============================================================================

var (
	barrierSecret      string
	barrierShares      []string
	barrierSharesFile  string
	barrierThreshold   int
	barrierTotal       int
	barrierAssumeYes   bool
	barrierStrategy    string
	barrierFlagSOPin   string
	barrierFlagUserPin string
	barrierRecoveryShs []string

	// enable-encryption (barrier migration) flags
	barrierEncTenantID     string
	barrierEncStrategy     string
	barrierEncMechanism    string
	barrierEncAvailability string
)

// =============================================================================
// Typed errors
// =============================================================================

// PINsNotAllowedError is returned when SO/User PINs are supplied to a
// barrier verb whose configured strategy forbids PIN authorization
// (currently --barrier-strategy=none).
type PINsNotAllowedError struct {
	Strategy string
	Op       string
}

// Error returns a human-readable description.
func (e *PINsNotAllowedError) Error() string {
	return "barrier " + e.Op + ": --so-pin/--user-pin are not allowed when --barrier-strategy=" + e.Strategy
}

// BarrierStrategyError is returned when --barrier-strategy is missing
// or carries an unrecognised value.
type BarrierStrategyError struct {
	Value string
}

// Error returns a human-readable description.
func (e *BarrierStrategyError) Error() string {
	if e.Value == "" {
		return "barrier init: --barrier-strategy is required (one of none, passphrase, shamir)"
	}
	return "barrier init: invalid --barrier-strategy " + strconvQuote(e.Value) +
		" (must be one of none, passphrase, shamir)"
}

// BarrierSecretRequiredError is returned when --passphrase is required for
// the selected strategy and was not supplied.
type BarrierSecretRequiredError struct {
	Op       string
	Strategy string
}

// Error returns a human-readable description.
func (e *BarrierSecretRequiredError) Error() string {
	if e.Strategy != "" {
		return "barrier " + e.Op + ": --passphrase is required when --barrier-strategy=" + e.Strategy
	}
	return "barrier " + e.Op + ": --passphrase is required"
}

// BarrierSecretNotAllowedError is returned when --passphrase was supplied
// to a verb / strategy combination that rejects it.
type BarrierSecretNotAllowedError struct {
	Op       string
	Strategy string
}

// Error returns a human-readable description.
func (e *BarrierSecretNotAllowedError) Error() string {
	return "barrier " + e.Op + ": --passphrase is not allowed when --barrier-strategy=" + e.Strategy
}

// PINPairError is returned when --so-pin / --user-pin are supplied
// without their dual-control counterpart.
type PINPairError struct {
	Op      string
	Missing string
}

// Error returns a human-readable description.
func (e *PINPairError) Error() string {
	return "barrier " + e.Op + ": " + e.Missing +
		" must be paired with its dual-control counterpart (FIPS 140-3 / PCI-DSS v4)"
}

// BarrierShamirParamsError is returned when --threshold / --total are
// invalid or violate the M <= N relation.
type BarrierShamirParamsError struct {
	Op     string
	Reason string
}

// Error returns a human-readable description.
func (e *BarrierShamirParamsError) Error() string {
	return "barrier " + e.Op + ": " + e.Reason
}

// BarrierShamirOnInitError is returned when --barrier-strategy=shamir
// is used with the `init` verb; the canonical surface routes Shamir
// initialization through `init-shamir`.
type BarrierShamirOnInitError struct{}

// Error returns a human-readable description.
func (e *BarrierShamirOnInitError) Error() string {
	return "barrier init: --barrier-strategy=shamir requires the 'init-shamir' verb " +
		"(supply --threshold and --total there)"
}

// BarrierShareInputError is returned when the --share / --shares-file
// invariants of `barrier unseal-shares` are violated.
type BarrierShareInputError struct {
	Reason string
}

// Error returns a human-readable description.
func (e *BarrierShareInputError) Error() string {
	return "barrier unseal-shares: " + e.Reason
}

// BarrierSharesFileError is returned when --shares-file cannot be read.
type BarrierSharesFileError struct {
	Path string
	Err  error
}

// Error returns a human-readable description.
func (e *BarrierSharesFileError) Error() string {
	return "barrier unseal-shares: failed to read --shares-file " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *BarrierSharesFileError) Unwrap() error { return e.Err }

// BarrierSharesFileEmptyError is returned when --shares-file contained
// no non-empty lines.
type BarrierSharesFileEmptyError struct {
	Path string
}

// Error returns a human-readable description.
func (e *BarrierSharesFileEmptyError) Error() string {
	return "barrier unseal-shares: --shares-file " + e.Path + " contains no shares"
}

// XKMSRekeyShamirParamsRequiredError is returned when `barrier rekey`
// is invoked without --threshold / --total. xkms's wire-level
// BarrierRekey only supports Shamir share regeneration; the server
// derives all secret material itself, so the verb carries no secret
// and the Shamir parameters are mandatory.
type XKMSRekeyShamirParamsRequiredError struct{}

// Error returns a human-readable description.
func (e *XKMSRekeyShamirParamsRequiredError) Error() string {
	return "barrier rekey: xkms only supports Shamir share regeneration; " +
		"provide --threshold and --total"
}

// BarrierRecoverySharesRequiredError is returned when `barrier recovery
// recover` is invoked without any --share flag.
type BarrierRecoverySharesRequiredError struct{}

// Error returns a human-readable description.
func (e *BarrierRecoverySharesRequiredError) Error() string {
	return "barrier recovery recover: --share is required (at least one)"
}

// BarrierEnableEncryptionStrategyRequiredError is returned when `barrier
// enable-encryption` is invoked without a --strategy flag.
type BarrierEnableEncryptionStrategyRequiredError struct{}

// Error returns a human-readable description.
func (e *BarrierEnableEncryptionStrategyRequiredError) Error() string {
	return "barrier enable-encryption: --strategy is required (e.g. passphrase or shamir)"
}

// BarrierSealConfirmationError is returned when interactive confirmation
// could not be read from stdin.
type BarrierSealConfirmationError struct {
	Err error
}

// Error returns a human-readable description.
func (e *BarrierSealConfirmationError) Error() string {
	return "barrier seal: failed to read confirmation: " + e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *BarrierSealConfirmationError) Unwrap() error { return e.Err }

// strconvQuote keeps the package import surface minimal — wrapping a
// single short string in quotes does not warrant pulling in strconv.
func strconvQuote(s string) string { return "\"" + s + "\"" }

// =============================================================================
// Command tree
// =============================================================================

// barrierCmd is the top-level barrier command group.
var barrierCmd = &cobra.Command{
	Use:   "barrier",
	Short: "Manage the cryptographic barrier",
	Long: `Manage the cryptographic barrier that protects the data encryption key.

The barrier must be initialized once and unsealed after each restart
before xkms can process cryptographic operations.

Verbs mirror qrdbctl / quicbaas / platformctl so operators have a single,
consistent surface across the stack:
  status         Show current barrier status
  init           Initialize with a single passphrase (or --barrier-strategy=none)
  init-shamir    Initialize with Shamir M-of-N secret sharing
  unseal         Unseal with --passphrase (single-secret)
  unseal-shares  Unseal with one or more Shamir shares (--share / --shares-file)
  seal           Seal the barrier
  rekey          Regenerate Shamir shares (--threshold/--total; no secret on the wire)
  recovery       Generate or use recovery keys (generate | recover)`,
}

// barrierStatusCmd shows barrier status.
var barrierStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current barrier status",
	Long: `Display the current state of the cryptographic barrier including
sealed/unsealed, the active strategy, hardware backing, and the
initialization timestamp.

Examples:
  xkmsctl barrier status
  xkmsctl barrier status --output json`,
	RunE: runBarrierStatusCmd,
}

// barrierInitCmd initializes the barrier with a single master key.
var barrierInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the cryptographic barrier",
	Long: `Initialize the cryptographic barrier.

Strategies:
  none       Identity passthrough; no master key is bound (dev / test only).
  passphrase Single passphrase-derived master key (default for production).
  shamir     Shamir M-of-N — use 'init-shamir' for this strategy.

--passphrase is required when --barrier-strategy is 'passphrase' and rejected
when --barrier-strategy is 'none'. PINs are optional but follow the
dual-control rule: supplying --so-pin requires --user-pin (and vice
versa). PINs are rejected entirely when --barrier-strategy=none.

Examples:
  xkmsctl barrier init --barrier-strategy passphrase --passphrase '<passphrase>'
  xkmsctl barrier init --barrier-strategy none
  xkmsctl barrier init --barrier-strategy passphrase --passphrase '<pp>' \
                       --so-pin SO12345 --user-pin USR12345`,
	RunE: runBarrierInitCmd,
}

// barrierInitShamirCmd initializes the barrier with Shamir secret sharing.
var barrierInitShamirCmd = &cobra.Command{
	Use:   "init-shamir",
	Short: "Initialize the barrier with Shamir M-of-N secret sharing",
	Long: `Initialize the barrier using Shamir M-of-N secret sharing.

The master secret is split into --total shares of which --threshold are
required to unseal. PIN flags are optional but follow the dual-control
rule -- supplying --so-pin requires --user-pin.

The generated shares are printed once; distribute them to custodians
immediately and out-of-band.

Example:
  xkmsctl barrier init-shamir --passphrase '<seed>' --threshold 3 --total 5`,
	RunE: runBarrierInitShamirCmd,
}

// barrierUnsealCmd unseals the barrier with a single passphrase.
var barrierUnsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal the barrier using a passphrase",
	Long: `Unseal the barrier using the master passphrase supplied at 'barrier
init' time.

This verb is reserved for the passphrase / single-secret strategy. For
Shamir M-of-N unseal use 'barrier unseal-shares' with --share or
--shares-file.

Example:
  xkmsctl barrier unseal --passphrase '<passphrase>'`,
	RunE: runBarrierUnsealCmd,
}

// barrierUnsealSharesCmd unseals the barrier by submitting Shamir shares.
var barrierUnsealSharesCmd = &cobra.Command{
	Use:   "unseal-shares",
	Short: "Unseal the barrier by submitting Shamir shares",
	Long: `Unseal the barrier using one or more Shamir shares.

Two input modes are supported; exactly one must be supplied:

  --share <value>      Repeatable. Supply one or more shares as flags.
  --shares-file <path> Newline-delimited file of shares; '-' reads from stdin.

Submitting a number of shares >= the M threshold unseals the barrier in
a single call.

Examples:
  xkmsctl barrier unseal-shares --share aaa --share bbb --share ccc
  xkmsctl barrier unseal-shares --shares-file /etc/xkms/shares.txt
  cat shares.txt | xkmsctl barrier unseal-shares --shares-file -`,
	RunE: runBarrierUnsealSharesCmd,
}

// barrierSealCmd seals the barrier.
var barrierSealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal the cryptographic barrier",
	Long: `Seal the barrier, zeroing the data encryption key.

All cryptographic operations are blocked until the barrier is unsealed
again. By default the command prompts for confirmation; pass
--assume-yes / -y to skip the prompt (e.g. in scripted runbooks).
Operators with a PINBackend configured MUST supply --so-pin; the CLI
verifies it before issuing the seal RPC.

Examples:
  xkmsctl barrier seal -y
  xkmsctl barrier seal --so-pin SO12345 --assume-yes`,
	RunE: runBarrierSealCmd,
}

// barrierRekeyCmd rotates the barrier master key.
var barrierRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Rotate the barrier master key",
	Long: `Regenerate the barrier's Shamir share set.

xkms's wire-level rekey supports Shamir share regeneration only: the
server generates the fresh secret material itself, so no secret travels
on the request. --threshold / --total define the new M-of-N layout and
are required. --so-pin is verified when supplied.

Example:
  xkmsctl barrier rekey --threshold 3 --total 5
  xkmsctl barrier rekey --so-pin SO12345 --threshold 3 --total 5`,
	RunE: runBarrierRekeyCmd,
}

// barrierRecoveryCmd is the parent for recovery-key management verbs.
var barrierRecoveryCmd = &cobra.Command{
	Use:   "recovery",
	Short: "Recovery key management",
	Long: `Generate and use recovery keys for disaster-recovery scenarios.

Canonical surface:
  recovery generate   Generate M-of-N recovery keys
  recovery recover    Restore the barrier from recovery keys`,
}

// barrierRecoveryGenerateCmd generates M-of-N recovery keys.
var barrierRecoveryGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate M-of-N recovery keys",
	Long: `Generate fresh recovery keys.

Recovery keys are independent of the barrier's unseal shares and live in
a parallel KMS slot. Generation requires --threshold (M) and --total
(N); --so-pin is verified when supplied.

Example:
  xkmsctl barrier recovery generate --threshold 3 --total 5 --so-pin SO12345`,
	RunE: runBarrierRecoveryGenerateCmd,
}

// barrierRecoveryRecoverCmd recovers the barrier with recovery keys.
var barrierRecoveryRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover the barrier using recovery keys",
	Long: `Recover the barrier by submitting M-of-N recovery keys.

--share is repeatable: pass each recovery key as its own --share flag.

Example:
  xkmsctl barrier recovery recover --share key-a --share key-b --share key-c`,
	RunE: runBarrierRecoveryRecoverCmd,
}

// barrierRecoveryDeleteKeysCmd deletes all stored recovery keys.
var barrierRecoveryDeleteKeysCmd = &cobra.Command{
	Use:   "delete-keys",
	Short: "Delete all stored recovery keys",
	Long: `Delete every stored recovery key. After deletion the barrier can no
longer be recovered with the previously generated recovery keys; generate a
fresh set with 'barrier recovery generate' if recovery capability is still
required.

Example:
  xkmsctl barrier recovery delete-keys`,
	RunE: runBarrierRecoveryDeleteKeysCmd,
}

// barrierRecoveryRootTokenCmd generates a root token from Shamir shares.
var barrierRecoveryRootTokenCmd = &cobra.Command{
	Use:   "root-token",
	Short: "Generate a root token from Shamir shares",
	Long: `Generate a privileged root token by submitting M-of-N Shamir shares.

--share is repeatable: pass each share as its own --share flag.

Example:
  xkmsctl barrier recovery root-token --share s-a --share s-b --share s-c`,
	RunE: runBarrierRecoveryRootTokenCmd,
}

// runBarrierRecoveryDeleteKeysCmd deletes all recovery keys via the SDK.
func runBarrierRecoveryDeleteKeysCmd(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := cl.BarrierDeleteRecoveryKeys(context.Background()); err != nil {
		return &WrappedError{Sentinel: ErrDeleteRecoveryKeysFailed, Err: err}
	}
	return printer.PrintSuccess("Recovery keys deleted")
}

// runBarrierRecoveryRootTokenCmd generates a root token via the SDK.
func runBarrierRecoveryRootTokenCmd(cmd *cobra.Command, _ []string) error {
	if len(barrierRecoveryShs) == 0 {
		return &BarrierRecoverySharesRequiredError{}
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := cl.BarrierGenerateRootToken(context.Background(), &transport.BarrierGenerateRootTokenRequest{
		Shares: barrierRecoveryShs,
	})
	if err != nil {
		return &WrappedError{Sentinel: ErrGenerateRootTokenFailed, Err: err}
	}

	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(resp)
	default:
		printer.printf("Root Token:\n  Token:      %s\n", resp.Token)
		if resp.CreatedAt != "" {
			printer.printf("  Created At: %s\n", resp.CreatedAt)
		}
		return printer.Err()
	}
}

// barrierEnableEncryptionCmd migrates an unencrypted barrier to a keyed strategy.
var barrierEnableEncryptionCmd = &cobra.Command{
	Use:   "enable-encryption",
	Short: "Enable at-rest encryption on an unencrypted barrier",
	Long: `Migrate a previously-unencrypted (none-strategy) barrier to a keyed
strategy in place. The migration runs asynchronously on the server; poll
'barrier status' until the reported strategy changes to the keyed target.

An empty --tenant-id targets the system barrier; otherwise the named tenant's
dedicated barrier is migrated. --strategy is required (e.g. passphrase or
shamir). --mechanism defaults to swap; --availability defaults to quiesced.

Examples:
  xkmsctl barrier enable-encryption --strategy passphrase --passphrase hunter2
  xkmsctl barrier enable-encryption --strategy shamir --threshold 3 --total 5
  xkmsctl barrier enable-encryption --tenant-id acme --strategy passphrase --passphrase s3cret`,
	RunE: runBarrierEnableEncryptionCmd,
}

// runBarrierEnableEncryptionCmd starts an enable-encryption migration.
func runBarrierEnableEncryptionCmd(cmd *cobra.Command, _ []string) error {
	if barrierEncStrategy == "" {
		return &BarrierEnableEncryptionStrategyRequiredError{}
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	resp, err := cl.BarrierEnableEncryption(ctx, &transport.BarrierEnableEncryptionRequest{
		TenantID:        barrierEncTenantID,
		Strategy:        barrierEncStrategy,
		Mechanism:       barrierEncMechanism,
		Availability:    barrierEncAvailability,
		Passphrase:      barrierSecret,
		ShamirThreshold: barrierThreshold,
		ShamirTotal:     barrierTotal,
	})
	if err != nil {
		return &WrappedError{Sentinel: ErrEnableEncryptionFailed, Err: err}
	}
	return printBarrierEnableEncryption(printer, resp)
}

// printBarrierEnableEncryption renders the enable-encryption acknowledgement.
func printBarrierEnableEncryption(printer *Printer, resp *transport.BarrierEnableEncryptionResponse) error {
	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{
			"status": resp.Status,
			"scope":  resp.Scope,
		})
	case OutputFormatTable, OutputFormatText:
		printer.printf("Encryption Migration Started\n")
		printer.printf("  Status: %s\n", resp.Status)
		printer.printf("  Scope:  %s\n", resp.Scope)
		printer.printf("\nThe migration runs asynchronously. Poll 'barrier status' until the\n")
		printer.printf("reported strategy changes from 'none' to the keyed target.\n")
		return printer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(printer.format)}
	}
}

// =============================================================================
// Client helper
// =============================================================================

// createBarrierClient creates and connects a client, returning the
// client and a cleanup function. The caller MUST call cleanup when done.
func createBarrierClient(cfg *Config) (client.Client, func(), error) {
	cl, err := cfg.CreateClient()
	if err != nil {
		return nil, nil, &WrappedError{Sentinel: ErrCreateClientFailed, Err: err}
	}

	ctx := context.Background()
	if err := cl.Connect(ctx); err != nil {
		closeQuietly(cl)
		return nil, nil, &WrappedError{Sentinel: ErrConnectFailed, Err: err}
	}

	cleanup := func() { closeQuietly(cl) }
	return cl, cleanup, nil
}

// =============================================================================
// PIN dispatch helpers
// =============================================================================

// verifySOPINIfSupplied calls VerifySOPIN against the SDK when the
// operator supplied --so-pin. The call is the canonical pre-flight
// guard for any post-init barrier verb that requires SO authorization.
func verifySOPINIfSupplied(ctx context.Context, cl client.Client, soPin string) error {
	if soPin == "" {
		return nil
	}
	return cl.VerifySOPIN(ctx, &transport.VerifySOPINRequest{SOPIN: soPin})
}

// applyInitialPINPair binds the supplied SO / User PIN pair to the xkms
// PIN backend AFTER a fresh barrier init. The SO PIN is set first (with
// an empty CurrentSOPIN because we are setting it for the first time),
// followed by the user PIN which itself is authorised by the SO PIN.
// Both calls are required; partial success is a server-side problem the
// caller bubbles back as a normal error.
func applyInitialPINPair(ctx context.Context, cl client.Client, soPin, userPin string) error {
	if soPin == "" && userPin == "" {
		return nil
	}
	if err := cl.SetSOPIN(ctx, &transport.SetSOPINRequest{
		CurrentSOPIN: "",
		NewSOPIN:     soPin,
	}); err != nil {
		return &WrappedError{Sentinel: ErrSetSOPINFailed, Err: err}
	}
	if err := cl.SetUserPIN(ctx, &transport.SetUserPINRequest{
		SOPIN:      soPin,
		NewUserPIN: userPin,
	}); err != nil {
		return &WrappedError{Sentinel: ErrSetUserPINFailed, Err: err}
	}
	return nil
}

// =============================================================================
// status
// =============================================================================

// runBarrierStatusCmd executes 'barrier status'.
func runBarrierStatusCmd(cmd *cobra.Command, _ []string) error {
	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	resp, err := cl.BarrierStatus(context.Background())
	if err != nil {
		return &WrappedError{Sentinel: ErrGetBarrierStatusFailed, Err: err}
	}
	return printBarrierStatus(printer, resp)
}

// =============================================================================
// init
// =============================================================================

// validateInitFlags applies the canonical init flag invariants and
// returns a typed error on the first violation. Centralising the
// validation in one place keeps the RunE handler small and lets tests
// drive each branch directly.
func validateInitFlags(strategy, secret, soPin, userPin string) error {
	if _, ok := barrierStrategyInit[strategy]; !ok {
		return &BarrierStrategyError{Value: strategy}
	}
	if strategy == "shamir" {
		return &BarrierShamirOnInitError{}
	}
	if strategy == "none" {
		if secret != "" {
			return &BarrierSecretNotAllowedError{Op: "init", Strategy: "none"}
		}
		if soPin != "" || userPin != "" {
			return &PINsNotAllowedError{Strategy: "none", Op: "init"}
		}
		return nil
	}
	// strategy == "passphrase"
	if secret == "" {
		return &BarrierSecretRequiredError{Op: "init", Strategy: strategy}
	}
	return validatePINPair("init", soPin, userPin)
}

// validatePINPair enforces the FIPS 140-3 / PCI-DSS v4 dual-control
// rule: --so-pin and --user-pin must be supplied together.
func validatePINPair(op, soPin, userPin string) error {
	if soPin != "" && userPin == "" {
		return &PINPairError{Op: op, Missing: "--so-pin"}
	}
	if userPin != "" && soPin == "" {
		return &PINPairError{Op: op, Missing: "--user-pin"}
	}
	return nil
}

// runBarrierInitCmd executes 'barrier init'.
func runBarrierInitCmd(cmd *cobra.Command, _ []string) error {
	if err := validateInitFlags(barrierStrategy, barrierSecret, barrierFlagSOPin, barrierFlagUserPin); err != nil {
		return err
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	if err := cl.BarrierInitialize(ctx, &transport.BarrierInitializeRequest{
		Secret: barrierSecret,
	}); err != nil {
		return &WrappedError{Sentinel: ErrInitializeBarrierFailed, Err: err}
	}

	if err := applyInitialPINPair(ctx, cl, barrierFlagSOPin, barrierFlagUserPin); err != nil {
		return err
	}

	return printer.PrintSuccess("Barrier initialized successfully")
}

// =============================================================================
// init-shamir
// =============================================================================

// validateInitShamirFlags applies the canonical init-shamir invariants.
func validateInitShamirFlags(secret string, threshold, total int, soPin, userPin string) error {
	if secret == "" {
		return &BarrierSecretRequiredError{Op: "init-shamir"}
	}
	if threshold <= 0 {
		return &BarrierShamirParamsError{Op: "init-shamir", Reason: "--threshold must be > 0"}
	}
	if total <= 0 {
		return &BarrierShamirParamsError{Op: "init-shamir", Reason: "--total must be > 0"}
	}
	if threshold > total {
		return &BarrierShamirParamsError{Op: "init-shamir", Reason: "--threshold cannot exceed --total"}
	}
	return validatePINPair("init-shamir", soPin, userPin)
}

// runBarrierInitShamirCmd executes 'barrier init-shamir'.
func runBarrierInitShamirCmd(cmd *cobra.Command, _ []string) error {
	if err := validateInitShamirFlags(barrierSecret, barrierThreshold, barrierTotal,
		barrierFlagSOPin, barrierFlagUserPin); err != nil {
		return err
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	resp, err := cl.BarrierInitializeShamir(ctx, &transport.BarrierInitializeShamirRequest{
		Secret:      barrierSecret,
		Threshold:   barrierThreshold,
		TotalShares: barrierTotal,
	})
	if err != nil {
		return &WrappedError{Sentinel: ErrInitializeShamirBarrierFailed, Err: err}
	}

	if err := applyInitialPINPair(ctx, cl, barrierFlagSOPin, barrierFlagUserPin); err != nil {
		return err
	}

	return printBarrierShamirResult(printer, resp)
}

// =============================================================================
// unseal
// =============================================================================

// runBarrierUnsealCmd executes 'barrier unseal'.
func runBarrierUnsealCmd(cmd *cobra.Command, _ []string) error {
	if barrierSecret == "" {
		return &BarrierSecretRequiredError{Op: "unseal"}
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := cl.BarrierUnseal(context.Background(), &transport.BarrierUnsealRequest{
		Secret: barrierSecret,
	}); err != nil {
		return &WrappedError{Sentinel: ErrUnsealBarrierFailed, Err: err}
	}

	return printer.PrintSuccess("Barrier unsealed successfully")
}

// =============================================================================
// unseal-shares
// =============================================================================

// resolveUnsealShares enforces the --share / --shares-file invariants
// and returns the flattened share list.
func resolveUnsealShares(shares []string, sharesFile string, stdin io.Reader) ([]string, error) {
	hasFlag := len(shares) > 0
	hasFile := sharesFile != ""
	if hasFlag && hasFile {
		return nil, &BarrierShareInputError{
			Reason: "exactly one of --share (repeatable) or --shares-file is allowed",
		}
	}
	if !hasFlag && !hasFile {
		return nil, &BarrierShareInputError{
			Reason: "one of --share (repeatable) or --shares-file is required",
		}
	}
	if hasFlag {
		return shares, nil
	}
	return readSharesFile(sharesFile, stdin)
}

// readSharesFile reads one share per line from path. Blank lines and
// '#' comments are skipped. The literal path "-" reads from the
// supplied stdin reader (defaults to os.Stdin in production).
func readSharesFile(path string, stdin io.Reader) ([]string, error) {
	var src io.Reader
	if path == "-" {
		src = stdin
		if src == nil {
			src = os.Stdin
		}
	} else {
		f, err := os.Open(path) // #nosec G304 - path supplied by operator
		if err != nil {
			return nil, &BarrierSharesFileError{Path: path, Err: err}
		}
		defer closeQuietly(f)
		src = f
	}

	var shares []string
	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shares = append(shares, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, &BarrierSharesFileError{Path: path, Err: err}
	}
	if len(shares) == 0 {
		return nil, &BarrierSharesFileEmptyError{Path: path}
	}
	return shares, nil
}

// runBarrierUnsealSharesCmd executes 'barrier unseal-shares'.
func runBarrierUnsealSharesCmd(cmd *cobra.Command, _ []string) error {
	shares, err := resolveUnsealShares(barrierShares, barrierSharesFile, cmd.InOrStdin())
	if err != nil {
		return err
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := cl.BarrierUnsealWithShares(context.Background(), &transport.BarrierUnsealSharesRequest{
		Shares: shares,
	}); err != nil {
		return &WrappedError{Sentinel: ErrUnsealBarrierSharesFailed, Err: err}
	}

	return printer.PrintSuccess("Barrier unsealed successfully")
}

// =============================================================================
// seal
// =============================================================================

// confirmBarrierSeal reads a yes/no confirmation from stdin unless the
// operator passed --assume-yes. Returns true when the operator confirmed.
func confirmBarrierSeal(in io.Reader, out io.Writer, assumeYes bool) (bool, error) {
	if assumeYes {
		return true, nil
	}
	if _, err := fmt.Fprint(out, "Are you sure you want to seal the barrier? (yes/no): "); err != nil {
		return false, &BarrierSealConfirmationError{Err: err}
	}
	reader := bufio.NewReader(in)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, &BarrierSealConfirmationError{Err: err}
	}
	return strings.TrimSpace(strings.ToLower(response)) == "yes", nil
}

// runBarrierSealCmd executes 'barrier seal'.
func runBarrierSealCmd(cmd *cobra.Command, _ []string) error {
	ok, err := confirmBarrierSeal(cmd.InOrStdin(), cmd.OutOrStdout(), barrierAssumeYes)
	if err != nil {
		return err
	}
	if !ok {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Seal cancelled"); err != nil {
			return err
		}
		return nil
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	if err := verifySOPINIfSupplied(ctx, cl, barrierFlagSOPin); err != nil {
		return &WrappedError{Sentinel: ErrVerifySOPINFailed, Err: err}
	}

	if err := cl.BarrierSeal(ctx); err != nil {
		return &WrappedError{Sentinel: ErrSealBarrierFailed, Err: err}
	}

	return printer.PrintSuccess("Barrier sealed successfully")
}

// =============================================================================
// rekey
// =============================================================================

// validateRekeyFlags enforces the canonical rekey invariants.
//
// xkms's wire-level BarrierRekey carries only Threshold/Total — it
// regenerates Shamir shares and the server derives all secret material
// itself, so the verb takes no secret flag at all.
func validateRekeyFlags(threshold, total int) error {
	hasThresh := threshold > 0
	hasTotal := total > 0
	if hasThresh != hasTotal {
		return &BarrierShamirParamsError{
			Op:     "rekey",
			Reason: "--threshold and --total must be supplied together",
		}
	}
	if !hasThresh && !hasTotal {
		return &XKMSRekeyShamirParamsRequiredError{}
	}
	if threshold > total {
		return &BarrierShamirParamsError{Op: "rekey", Reason: "--threshold cannot exceed --total"}
	}
	return nil
}

// runBarrierRekeyCmd executes 'barrier rekey'.
func runBarrierRekeyCmd(cmd *cobra.Command, _ []string) error {
	if err := validateRekeyFlags(barrierThreshold, barrierTotal); err != nil {
		return err
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	if err := verifySOPINIfSupplied(ctx, cl, barrierFlagSOPin); err != nil {
		return &WrappedError{Sentinel: ErrVerifySOPINFailed, Err: err}
	}

	resp, err := cl.BarrierRekey(ctx, &transport.BarrierRekeyRequest{
		Threshold: barrierThreshold,
		Total:     barrierTotal,
	})
	if err != nil {
		return &WrappedError{Sentinel: ErrRekeyBarrierFailed, Err: err}
	}
	return printBarrierRekeyResult(printer, resp)
}

// =============================================================================
// recovery generate
// =============================================================================

// validateRecoveryGenerateFlags enforces the canonical recovery-gen invariants.
func validateRecoveryGenerateFlags(threshold, total int) error {
	if threshold < 2 {
		return &BarrierShamirParamsError{
			Op:     "recovery generate",
			Reason: "--threshold must be >= 2",
		}
	}
	if total < threshold {
		return &BarrierShamirParamsError{
			Op:     "recovery generate",
			Reason: "--total must be >= --threshold",
		}
	}
	return nil
}

// runBarrierRecoveryGenerateCmd executes 'barrier recovery generate'.
func runBarrierRecoveryGenerateCmd(cmd *cobra.Command, _ []string) error {
	if err := validateRecoveryGenerateFlags(barrierThreshold, barrierTotal); err != nil {
		return err
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx := context.Background()
	if err := verifySOPINIfSupplied(ctx, cl, barrierFlagSOPin); err != nil {
		return &WrappedError{Sentinel: ErrVerifySOPINFailed, Err: err}
	}

	resp, err := cl.BarrierGenerateRecoveryKeys(ctx, &transport.BarrierGenerateRecoveryKeysRequest{
		Threshold: barrierThreshold,
		Total:     barrierTotal,
	})
	if err != nil {
		return &WrappedError{Sentinel: ErrGenerateRecoveryKeysFailed, Err: err}
	}
	return printBarrierRecoveryKeys(printer, resp)
}

// =============================================================================
// recovery recover
// =============================================================================

// runBarrierRecoveryRecoverCmd executes 'barrier recovery recover'.
func runBarrierRecoveryRecoverCmd(cmd *cobra.Command, _ []string) error {
	if len(barrierRecoveryShs) == 0 {
		return &BarrierRecoverySharesRequiredError{}
	}

	cfg := getConfig()
	printer := NewPrinter(cfg.OutputFormat, cmd.OutOrStdout())

	cl, cleanup, err := createBarrierClient(cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := cl.BarrierRecoverWithKeys(context.Background(), &transport.BarrierRecoverWithKeysRequest{
		Keys: barrierRecoveryShs,
	}); err != nil {
		return &WrappedError{Sentinel: ErrRecoverBarrierFailed, Err: err}
	}
	return printer.PrintSuccess("Barrier recovered successfully")
}

// =============================================================================
// Output helpers
// =============================================================================

// printBarrierStatus renders a BarrierStatusResponse.
func printBarrierStatus(printer *Printer, resp *transport.BarrierStatusResponse) error {
	switch printer.format {
	case OutputFormatJSON:
		result := map[string]interface{}{
			"sealed":          resp.Sealed,
			"strategy":        resp.Strategy,
			"hardware_backed": resp.HardwareBacked,
		}
		if resp.InitializedAt != "" {
			result["initialized_at"] = resp.InitializedAt
		}
		return printer.PrintJSON(result)
	case OutputFormatTable, OutputFormatText:
		state := "unsealed"
		if resp.Sealed {
			state = "sealed"
		}
		printer.printf("Barrier Status:\n")
		printer.printf("  State:           %s\n", state)
		printer.printf("  Strategy:        %s\n", resp.Strategy)
		printer.printf("  Hardware Backed: %t\n", resp.HardwareBacked)
		if resp.InitializedAt != "" {
			printer.printf("  Initialized At:  %s\n", resp.InitializedAt)
		}
		return printer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(printer.format)}
	}
}

// printBarrierShamirResult renders a Shamir initialization response.
// Share material is never returned (qrdb share-free contract): shares are
// sealed to enrolled Security Officers, who claim them individually.
func printBarrierShamirResult(printer *Printer, resp *transport.BarrierInitializeShamirResponse) error {
	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{
			"threshold":    resp.Threshold,
			"total_shares": resp.TotalShares,
			"share_count":  resp.ShareCount,
		})
	case OutputFormatTable, OutputFormatText:
		printer.printf("Shamir Secret Sharing Initialized\n")
		printer.printf("  Threshold:    %d of %d shares required\n",
			resp.Threshold, resp.TotalShares)
		printer.printf("  Shares Generated: %d\n", resp.ShareCount)
		printer.printf("\nShares are sealed to enrolled Security Officers and are never\n")
		printer.printf("displayed. Each officer must claim their share individually.\n")
		return printer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(printer.format)}
	}
}

// printBarrierRekeyResult renders a rekey response.
// New shares are sealed to enrolled Security Officers and never returned
// (qrdb share-free contract); only the threshold/total metadata is shown.
func printBarrierRekeyResult(printer *Printer, resp *transport.BarrierRekeyResponse) error {
	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{
			"threshold":    resp.Threshold,
			"total_shares": resp.TotalShares,
			"share_count":  resp.ShareCount,
		})
	case OutputFormatTable, OutputFormatText:
		printer.printf("Barrier Rekey Complete\n")
		printer.printf("  New Threshold: %d of %d\n", resp.Threshold, resp.TotalShares)
		printer.printf("  Shares Generated: %d\n", resp.ShareCount)
		printer.printf("\nNew shares are sealed to enrolled Security Officers and are never\n")
		printer.printf("displayed. Each officer must claim their new share individually.\n")
		return printer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(printer.format)}
	}
}

// printBarrierRecoveryKeys renders a recovery-key generation response.
// Recovery shares are sealed to enrolled recovery officers and never
// returned (qrdb share-free contract); only the metadata is shown.
func printBarrierRecoveryKeys(printer *Printer, resp *transport.BarrierRecoveryKeysResponse) error {
	switch printer.format {
	case OutputFormatJSON:
		return printer.PrintJSON(map[string]interface{}{
			"threshold":    resp.Threshold,
			"total_shares": resp.TotalShares,
			"share_count":  resp.ShareCount,
		})
	case OutputFormatTable, OutputFormatText:
		printer.printf("Recovery Keys Generated\n")
		printer.printf("  Threshold: %d of %d keys required\n",
			resp.Threshold, resp.TotalShares)
		printer.printf("  Shares Generated: %d\n", resp.ShareCount)
		printer.printf("\nRecovery shares are sealed to enrolled recovery officers and are\n")
		printer.printf("never displayed. Each officer must claim their share individually.\n")
		return printer.Err()
	default:
		return &WrappedDetailError{Sentinel: ErrUnknownOutputFormat, Detail: string(printer.format)}
	}
}

// =============================================================================
// Flag wiring
// =============================================================================

func init() {
	// init flags
	barrierInitCmd.Flags().StringVar(&barrierStrategy, "barrier-strategy", "passphrase",
		"Barrier strategy: none | passphrase | shamir")
	barrierInitCmd.Flags().StringVar(&barrierSecret, "passphrase", "",
		"Master passphrase (required for passphrase strategy, rejected for none)")
	barrierInitCmd.Flags().StringVar(&barrierFlagSOPin, "so-pin", "",
		"Security Officer PIN (optional; requires --user-pin; rejected for --barrier-strategy=none)")
	barrierInitCmd.Flags().StringVar(&barrierFlagUserPin, "user-pin", "",
		"User PIN (optional; requires --so-pin; rejected for --barrier-strategy=none)")

	// init-shamir flags
	barrierInitShamirCmd.Flags().StringVar(&barrierSecret, "passphrase", "",
		"Master passphrase (required)")
	barrierInitShamirCmd.Flags().IntVar(&barrierThreshold, "threshold", 0,
		"Minimum shares required to unseal (M)")
	barrierInitShamirCmd.Flags().IntVar(&barrierTotal, "total", 0,
		"Total number of shares to generate (N)")
	barrierInitShamirCmd.Flags().StringVar(&barrierFlagSOPin, "so-pin", "",
		"Security Officer PIN (optional; requires --user-pin)")
	barrierInitShamirCmd.Flags().StringVar(&barrierFlagUserPin, "user-pin", "",
		"User PIN (optional; requires --so-pin)")

	// unseal flags
	barrierUnsealCmd.Flags().StringVar(&barrierSecret, "passphrase", "",
		"Master passphrase (required)")

	// unseal-shares flags
	barrierUnsealSharesCmd.Flags().StringSliceVar(&barrierShares, "share", nil,
		"Single Shamir share (repeatable: --share a --share b ...)")
	barrierUnsealSharesCmd.Flags().StringVar(&barrierSharesFile, "shares-file", "",
		"Path to a newline-delimited share file; '-' for stdin")

	// seal flags
	barrierSealCmd.Flags().StringVar(&barrierFlagSOPin, "so-pin", "",
		"Security Officer PIN (verified before the seal RPC when supplied)")
	barrierSealCmd.Flags().BoolVarP(&barrierAssumeYes, "assume-yes", "y", false,
		"Skip the interactive confirmation prompt")

	// rekey flags — no secret flag: the server generates the fresh
	// secret material itself (xkms wire is Shamir-only).
	barrierRekeyCmd.Flags().StringVar(&barrierFlagSOPin, "so-pin", "",
		"Security Officer PIN (verified before the rekey RPC when supplied)")
	barrierRekeyCmd.Flags().IntVar(&barrierThreshold, "threshold", 0,
		"New Shamir threshold (paired with --total)")
	barrierRekeyCmd.Flags().IntVar(&barrierTotal, "total", 0,
		"New Shamir total share count (paired with --threshold)")

	// recovery generate flags
	barrierRecoveryGenerateCmd.Flags().IntVar(&barrierThreshold, "threshold", 0,
		"Minimum keys required for recovery (M)")
	barrierRecoveryGenerateCmd.Flags().IntVar(&barrierTotal, "total", 0,
		"Total number of recovery keys (N)")
	barrierRecoveryGenerateCmd.Flags().StringVar(&barrierFlagSOPin, "so-pin", "",
		"Security Officer PIN (verified before the generate RPC when supplied)")

	// recovery recover flags
	barrierRecoveryRecoverCmd.Flags().StringSliceVar(&barrierRecoveryShs, "share", nil,
		"Recovery key (repeatable: --share a --share b ...)")

	// enable-encryption flags
	barrierEnableEncryptionCmd.Flags().StringVar(&barrierEncTenantID, "tenant-id", "",
		"Tenant whose barrier to migrate (empty = system barrier)")
	barrierEnableEncryptionCmd.Flags().StringVar(&barrierEncStrategy, "strategy", "",
		"Keyed target strategy (e.g. passphrase, shamir) (required)")
	barrierEnableEncryptionCmd.Flags().StringVar(&barrierEncMechanism, "mechanism", "",
		"Re-encryption mechanism: swap (default) or in-place")
	barrierEnableEncryptionCmd.Flags().StringVar(&barrierEncAvailability, "availability", "",
		"Write availability during migration: quiesced (default) or online")
	barrierEnableEncryptionCmd.Flags().StringVar(&barrierSecret, "passphrase", "",
		"Passphrase for a passphrase-target migration")
	barrierEnableEncryptionCmd.Flags().IntVar(&barrierThreshold, "threshold", 0,
		"Shamir threshold (M) for a shamir-target migration")
	barrierEnableEncryptionCmd.Flags().IntVar(&barrierTotal, "total", 0,
		"Shamir total shares (N) for a shamir-target migration")

	// Build subcommand tree
	barrierRecoveryCmd.AddCommand(barrierRecoveryGenerateCmd)
	barrierRecoveryCmd.AddCommand(barrierRecoveryRecoverCmd)
	barrierRecoveryCmd.AddCommand(barrierRecoveryDeleteKeysCmd)
	barrierRecoveryCmd.AddCommand(barrierRecoveryRootTokenCmd)
	barrierRecoveryRootTokenCmd.Flags().StringSliceVar(&barrierRecoveryShs, "share", nil,
		"Shamir share (repeatable); pass each share as its own --share flag")

	barrierCmd.AddCommand(barrierStatusCmd)
	barrierCmd.AddCommand(barrierInitCmd)
	barrierCmd.AddCommand(barrierInitShamirCmd)
	barrierCmd.AddCommand(barrierUnsealCmd)
	barrierCmd.AddCommand(barrierUnsealSharesCmd)
	barrierCmd.AddCommand(barrierSealCmd)
	barrierCmd.AddCommand(barrierRekeyCmd)
	barrierCmd.AddCommand(barrierRecoveryCmd)
	barrierCmd.AddCommand(barrierEnableEncryptionCmd)
}
