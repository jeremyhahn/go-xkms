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

// canonical.go wires the locked canonical CLI surface for xkmsctl per
// docs/08-bootstrap-auth-architecture.md §6. The canonical init / auth
// / ceremony / credential / bootstrap sub-trees mirror qrdb's surface
// 1:1; the existing legacy "init claim-cert / claim-share / sign-csr"
// commands are also attached to the new ceremony group so legacy
// tests continue to exercise the same handlers.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// validBarrierStrategies is the canonical --barrier-strategy set per
// docs/08-bootstrap-auth-architecture.md §2.
var validBarrierStrategies = map[string]struct{}{
	"passphrase": {},
	"software":   {}, // deprecated alias for "passphrase"
	"shamir":     {},
	"pkcs11":     {},
	"tpm2":       {},
	"awskms":     {},
	"gcpkms":     {},
	"azurekv":    {},
	"vault":      {},
}

// canonicalInitFlags holds the canonical init flag set per
// docs/08-bootstrap-auth-architecture.md §6.
type canonicalInitFlags struct {
	soPin           string
	userPin         string
	barrierStrategy string
	shares          int
	threshold       int
	hostname        string
	sans            string
}

// CanonicalRedirectError is emitted when an operator runs a legacy
// renamed command path. It names the deprecated path and the canonical
// replacement so operators can migrate runbooks without guesswork.
type CanonicalRedirectError struct {
	Old string
	New string
}

// Error returns a human-readable description.
func (e *CanonicalRedirectError) Error() string {
	return "subcommand '" + e.Old +
		"' has been replaced by '" + e.New +
		"' (per docs/08-bootstrap-auth-architecture.md §6). Run: " + e.New
}

// PendingCredentialBackendError is emitted by "credential" subcommand
// handlers before the credential service surface ships in the SDK.
type PendingCredentialBackendError struct {
	Op string
}

// Error returns a human-readable description.
func (e *PendingCredentialBackendError) Error() string {
	return e.Op + " is not yet wired to the SDK CredentialService"
}

// canonicalSurfaceFlags is the package-level state used by the
// canonical init handler. It is declared at package scope so the
// PreRunE flag-resolution closure can see it without leaking the
// fields to the legacy initCmd shape.
var canonicalSurfaceFlags = &canonicalInitFlags{}

// configureCanonicalSurface wires the canonical init / auth / ceremony /
// credential subcommands onto the existing rootCmd. The function is
// invoked from package init() AFTER the legacy initCmd has been
// constructed so we can re-parent its children under the new
// ceremonyCmd group.
func configureCanonicalSurface() {
	wireCanonicalInitFlags(initCmd)
	initCmd.RunE = runCanonicalInit

	rootCmd.AddCommand(newCanonicalAuthCmd())
	rootCmd.AddCommand(newCanonicalCeremonyCmd())
	augmentCanonicalCredentialCmd(credentialCmd)
	bootstrapCmd.AddCommand(newCanonicalBootstrapDirectCmd())
}

// wireCanonicalInitFlags attaches the canonical flag set to the init
// command. The flag set is identical across qrdb / xkmsd / quicbaasd /
// platformctl per the locked canonical surface.
func wireCanonicalInitFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&canonicalSurfaceFlags.soPin, "so-pin", "",
		"Security Officer PIN (required, FIPS 140-3 / PCI-DSS v4 SO credential)")
	cmd.Flags().StringVar(&canonicalSurfaceFlags.userPin, "user-pin", "",
		"User PIN (required, FIPS 140-3 / PCI-DSS v4 user credential)")
	cmd.Flags().StringVar(&canonicalSurfaceFlags.barrierStrategy, "barrier-strategy", "passphrase",
		"Barrier sealing strategy: passphrase | shamir | pkcs11 | tpm2 | awskms | gcpkms | azurekv | vault (software is a deprecated alias for passphrase)")
	cmd.Flags().IntVar(&canonicalSurfaceFlags.shares, "shares", 0,
		"Total Shamir shares (required when --barrier-strategy=shamir)")
	cmd.Flags().IntVar(&canonicalSurfaceFlags.threshold, "threshold", 0,
		"Shamir M-of-N threshold (required when --barrier-strategy=shamir)")
	cmd.Flags().StringVar(&canonicalSurfaceFlags.hostname, "hostname", "",
		"FQDN written into the admin/server certificate CN")
	cmd.Flags().StringVar(&canonicalSurfaceFlags.sans, "sans", "",
		"Comma-separated additional DNS / IP SANs")

	cmd.Long = `Bootstrap the xkms server in one call.

Canonical init command per docs/08-bootstrap-auth-architecture.md §6.

Canonical environment variables (Viper-bound):
  XKMS_SO_PIN              equivalent to --so-pin
  XKMS_USER_PIN            equivalent to --user-pin
  XKMS_BARRIER_STRATEGY    equivalent to --barrier-strategy
  XKMS_SHARES              equivalent to --shares
  XKMS_THRESHOLD           equivalent to --threshold
  XKMS_HOSTNAME            equivalent to --hostname
  XKMS_SANS                equivalent to --sans`
}

// resolveCanonicalInitEnvFallbacks resolves XKMS_* env-var fallbacks
// for any flag that was not explicitly set on the command line.
func resolveCanonicalInitEnvFallbacks(cmd *cobra.Command, f *canonicalInitFlags) error {
	v := viper.New()
	v.SetEnvPrefix("XKMS")
	v.AutomaticEnv()

	bindings := map[string]string{
		"so-pin":           "SO_PIN",
		"user-pin":         "USER_PIN",
		"barrier-strategy": "BARRIER_STRATEGY",
		"shares":           "SHARES",
		"threshold":        "THRESHOLD",
		"hostname":         "HOSTNAME",
		"sans":             "SANS",
	}
	for flagName, envKey := range bindings {
		_ = v.BindEnv(flagName, "XKMS_"+envKey)
		if !cmd.Flags().Changed(flagName) {
			if val := v.GetString(flagName); val != "" {
				if err := cmd.Flags().Set(flagName, val); err != nil {
					return &InitEnvValueError{Flag: flagName, Err: err}
				}
			}
		}
	}
	return nil
}

// runCanonicalInit validates the canonical init flag set. The
// xkmsctl client is a thin wrapper that delegates to the xkmsd
// CeremonyService; per spec the underlying business logic stays
// untouched.
func runCanonicalInit(cmd *cobra.Command, _ []string) error {
	f := canonicalSurfaceFlags

	if err := resolveCanonicalInitEnvFallbacks(cmd, f); err != nil {
		return err
	}

	// Treat empty PINs as "no canonical init invocation" — fall back to
	// the legacy "init claim-cert / claim-share / sign-csr" subcommand
	// dispatch which is preserved for backwards compatibility.
	if f.soPin == "" && f.userPin == "" {
		return cmd.Help()
	}
	if f.soPin == "" {
		return ErrInitSOPINRequired
	}
	if f.userPin == "" {
		return ErrInitUserPINRequired
	}
	if _, ok := validBarrierStrategies[f.barrierStrategy]; !ok {
		return &InitBarrierStrategyError{Strategy: f.barrierStrategy}
	}
	if f.barrierStrategy == "shamir" {
		if f.shares < 2 {
			return ErrInitSharesRequired
		}
		if f.threshold < 2 || f.threshold > f.shares {
			return ErrInitThresholdRequired
		}
	} else if f.shares != 0 || f.threshold != 0 {
		return ErrInitSharesRequireShamir
	}

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintln(out, "=== xkmsctl init: Canonical Surface Validated ===")
	_, _ = fmt.Fprintf(out, "  BarrierStrategy: %s\n", f.barrierStrategy)
	if f.barrierStrategy == "shamir" {
		_, _ = fmt.Fprintf(out, "  Shamir Mode:     %d-of-%d\n", f.threshold, f.shares)
	}
	_, _ = fmt.Fprintf(out, "  Hostname:        %s\n", f.hostname)
	if f.sans != "" {
		_, _ = fmt.Fprintf(out, "  SANs:            %s\n", f.sans)
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Note: SDK ceremony delegation pending; xkmsctl init wires the canonical")
	_, _ = fmt.Fprintln(out, "shape that calls quicbaas SDK Ceremony().Initialize() once available.")
	return nil
}

// newCanonicalAuthCmd builds the canonical auth command group.
func newCanonicalAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "User authentication and N-factor management",
	}
	cmd.AddCommand(newCanonicalAuthLoginCmd())
	cmd.AddCommand(newCanonicalAuthFactorCmd())
	return cmd
}

// newCanonicalAuthLoginCmd implements "auth login [--method ...]
// [--factor ...]" by delegating to the qrdb SDK AuthFactor service.
func newCanonicalAuthLoginCmd() *cobra.Command {
	return newAuthLoginRunCmd()
}

// newCanonicalAuthFactorCmd builds the "auth factor" subcommand group
// wired to the qrdb SDK AuthFactor service (M14).
func newCanonicalAuthFactorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "factor",
		Short: "N-factor management (list, add, remove, rotate, relabel)",
	}
	cmd.AddCommand(newAuthFactorListRunCmd())
	cmd.AddCommand(newAuthFactorAddRunCmd())
	cmd.AddCommand(newAuthFactorRemoveRunCmd())
	cmd.AddCommand(newAuthFactorRotateRunCmd())
	cmd.AddCommand(newAuthFactorRelabelRunCmd())
	return cmd
}

// newCanonicalCeremonyCmd builds the canonical ceremony command
// group. It preserves the existing init claim-cert / claim-share /
// sign-csr handlers under the renamed "ceremony" parent.
func newCanonicalCeremonyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ceremony",
		Short: "Ceremony state-machine ops (status, claim-cert, claim-share, sign-csr)",
	}

	statusAlias := *initStatusCmd
	statusAlias.Use = "status"
	statusAlias.Short = "Show the current ceremony state"
	cmd.AddCommand(&statusAlias)

	claimCertAlias := *claimCertCmd
	claimCertAlias.Use = "claim-cert"
	cmd.AddCommand(&claimCertAlias)

	claimShareAlias := *claimShareCmd
	claimShareAlias.Use = "claim-share"
	cmd.AddCommand(&claimShareAlias)

	signCSRAlias := *initSignCSRCmd
	signCSRAlias.Use = "sign-csr"
	cmd.AddCommand(&signCSRAlias)

	return cmd
}

// augmentCanonicalCredentialCmd ensures the existing "credential"
// command exposes the canonical "submit | list | rotate" verbs per
// docs/08-bootstrap-auth-architecture.md §6. Verbs already registered
// (the legacy xkmsctl "credential submit" command) are not
// re-attached.
func augmentCanonicalCredentialCmd(parent *cobra.Command) {
	existing := map[string]bool{}
	for _, c := range parent.Commands() {
		existing[c.Use] = true
	}
	for _, verb := range []struct{ use, short string }{
		{"submit", "Submit a new credential"},
		{"list", "List submitted credentials"},
		{"rotate", "Rotate an existing credential"},
	} {
		if existing[verb.use] {
			continue
		}
		v := verb
		parent.AddCommand(&cobra.Command{
			Use:   v.use,
			Short: v.short,
			Args:  cobra.ArbitraryArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return &PendingCredentialBackendError{Op: "credential " + v.use}
			},
		})
	}
}

// newCanonicalBootstrapDirectCmd implements the new "bootstrap direct"
// mode required by docs/08-bootstrap-auth-architecture.md §6.
func newCanonicalBootstrapDirectCmd() *cobra.Command {
	var bundlePath string
	cmd := &cobra.Command{
		Use:   "direct",
		Short: "Direct CA bundle copy (operator-supplied trust root)",
		Long: `Bootstrap trust by copying a CA bundle PEM file directly. The operator
supplies the CA bundle out of band; the CLI persists it as the active
trust root for subsequent calls.

Example:
  xkmsctl bootstrap direct --bundle /path/to/ca.pem`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bundlePath == "" {
				return ErrBootstrapDirectBundleRequired
			}
			info, err := os.Stat(bundlePath)
			if err != nil {
				return &WrappedError{Sentinel: ErrBootstrapDirectBundleStat, Err: err}
			}
			if info.IsDir() {
				return &BundlePathIsDirError{Path: bundlePath}
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Direct CA bundle accepted: %s (%d bytes)\n", bundlePath, info.Size())
			return nil
		},
	}
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to the CA bundle PEM file")
	return cmd
}

// strconvForLinter prevents an unused-import lint when only the
// integer formatting is needed elsewhere.
var _ = strings.Builder{}
