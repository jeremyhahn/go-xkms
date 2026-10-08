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
// docs/08-bootstrap-auth-architecture.md §6. The canonical auth /
// credential / bootstrap sub-trees mirror qrdb's surface. The init
// ceremony and holder quorum verbs are qrdb's own (qrdb ceremony,
// barrier and holder commands); xkmsctl carries no copy of them.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// PendingCredentialBackendError is emitted by "credential" subcommand
// handlers before the credential service surface ships in the SDK.
type PendingCredentialBackendError struct {
	Op string
}

// Error returns a human-readable description.
func (e *PendingCredentialBackendError) Error() string {
	return e.Op + " is not yet wired to the SDK CredentialService"
}

// configureCanonicalSurface wires the canonical auth / credential
// subcommands onto the existing rootCmd.
func configureCanonicalSurface() {
	rootCmd.AddCommand(newCanonicalAuthCmd())
	augmentCanonicalCredentialCmd(credentialCmd)
	bootstrapCmd.AddCommand(newCanonicalBootstrapDirectCmd())
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
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Direct CA bundle accepted: %s (%d bytes)\n", bundlePath, info.Size()); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to the CA bundle PEM file")
	return cmd
}
