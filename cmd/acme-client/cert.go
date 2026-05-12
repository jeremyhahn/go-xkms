// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
)

// certRequestCmd requests a new certificate for a named spec.
var certRequestCmd = &cobra.Command{
	Use:   "request <name>",
	Short: "Request a new certificate",
	Long: `Request a new certificate from the ACME server for the named
certificate spec defined in the configuration.

The certificate spec must already be configured with the desired subject,
SANs, key parameters, and challenge type.

Examples:
  trusted-acme-client cert request web-prod
  trusted-acme-client cert request host-identity`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		result, err := svc.Certificates().Request(cmd.Context(), name)
		if err != nil {
			return err
		}

		cmd.Printf("Certificate %q issued successfully\n", name)
		cmd.Printf("  Subject: %s\n", result.Certificate.Subject.CommonName)
		cmd.Printf("  Expires: %s\n", result.Certificate.NotAfter.Format("2006-01-02"))
		return nil
	},
}

// certListCmd lists all configured certificate specs.
var certListCmd = &cobra.Command{
	Use:   "list",
	Short: "List certificate specs",
	Long: `List all configured certificate specs showing the spec name,
associated account, subject, and challenge type.

Optionally filter by account name.

Examples:
  trusted-acme-client cert list
  trusted-acme-client cert list --account trusted-ca`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		accountFilter, _ := cmd.Flags().GetString("account")
		specs := svc.Certificates().List(accountFilter)

		if len(specs) == 0 {
			cmd.Println("No certificate specs configured.")
			return nil
		}

		// Collect and sort spec names for deterministic output.
		names := make([]string, 0, len(specs))
		for name := range specs {
			names = append(names, name)
		}
		sort.Strings(names)

		// Calculate column widths for aligned output.
		nameWidth := len("NAME")
		acctWidth := len("ACCOUNT")
		subjWidth := len("SUBJECT")
		for _, name := range names {
			spec := specs[name]
			if len(name) > nameWidth {
				nameWidth = len(name)
			}
			if len(spec.Account) > acctWidth {
				acctWidth = len(spec.Account)
			}
			if len(spec.Subject.CN) > subjWidth {
				subjWidth = len(spec.Subject.CN)
			}
		}

		cmd.Printf("%-*s  %-*s  %-*s  %s\n", nameWidth, "NAME", acctWidth, "ACCOUNT", subjWidth, "SUBJECT", "CHALLENGE")
		for _, name := range names {
			spec := specs[name]
			challenge := spec.Challenge
			if challenge == "" {
				challenge = "http-01"
			}
			cmd.Printf("%-*s  %-*s  %-*s  %s\n", nameWidth, name, acctWidth, spec.Account, subjWidth, spec.Subject.CN, challenge)
		}

		return nil
	},
}

// certShowCmd displays detailed information about a managed certificate.
var certShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show certificate details",
	Long: `Display detailed information about a managed certificate including
account, subject, SANs, key configuration, challenge type, status,
expiration, and renewal settings.

Examples:
  trusted-acme-client cert show web-prod`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		info, err := svc.Certificates().Show(name)
		if err != nil {
			// Fall back to showing the spec if the cert has not been issued yet.
			specs := svc.Certificates().List("")
			spec, ok := specs[name]
			if !ok {
				return err
			}
			printUnissuedSpec(cmd, name, spec)
			return nil
		}

		printManagedCert(cmd, name, info)
		return nil
	},
}

// certRenewCmd renews an existing managed certificate.
var certRenewCmd = &cobra.Command{
	Use:   "renew <name>",
	Short: "Renew a managed certificate",
	Long: `Renew a managed certificate by performing a new ACME certificate
request using the existing certificate spec configuration.

Examples:
  trusted-acme-client cert renew web-prod`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		result, err := svc.Certificates().Renew(cmd.Context(), name)
		if err != nil {
			return err
		}

		cmd.Printf("Certificate %q renewed successfully\n", name)
		cmd.Printf("  Subject: %s\n", result.Certificate.Subject.CommonName)
		cmd.Printf("  Expires: %s\n", result.Certificate.NotAfter.Format("2006-01-02"))
		return nil
	},
}

// certRevokeCmd revokes a managed certificate.
var certRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke a managed certificate",
	Long: `Revoke a managed certificate with the ACME server using the
specified CRL reason code.

Reason codes (RFC 5280):
  0  unspecified
  1  keyCompromise
  3  affiliationChanged
  4  superseded
  5  cessationOfOperation

Examples:
  trusted-acme-client cert revoke web-prod
  trusted-acme-client cert revoke web-prod --reason 1`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		reason, _ := cmd.Flags().GetInt("reason")

		if err := svc.Certificates().Revoke(cmd.Context(), name, reason); err != nil {
			return err
		}

		cmd.Printf("Certificate %q revoked successfully\n", name)
		return nil
	},
}

// certDeployCmd deploys a managed certificate to the configured paths.
var certDeployCmd = &cobra.Command{
	Use:   "deploy <name>",
	Short: "Deploy a managed certificate",
	Long: `Deploy a managed certificate by writing the certificate and key
to the paths configured in the certificate spec. Optionally executes
a post-deployment hook command.

Examples:
  trusted-acme-client cert deploy web-prod`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		svc, err := createService()
		if err != nil {
			return err
		}

		name := args[0]
		if err := svc.Certificates().Deploy(cmd.Context(), name); err != nil {
			return err
		}

		cmd.Printf("Certificate %q deployed successfully\n", name)
		return nil
	},
}

func init() {
	// Flags for cert list.
	certListCmd.Flags().String("account", "", "filter by account name")

	// Flags for cert revoke.
	certRevokeCmd.Flags().Int("reason", 0, "CRL reason code (0=unspecified, 1=keyCompromise, 4=superseded)")

	certCmd.AddCommand(certRequestCmd)
	certCmd.AddCommand(certListCmd)
	certCmd.AddCommand(certShowCmd)
	certCmd.AddCommand(certRenewCmd)
	certCmd.AddCommand(certRevokeCmd)
	certCmd.AddCommand(certDeployCmd)
}

// printManagedCert prints detailed information about an issued managed certificate.
func printManagedCert(cmd *cobra.Command, name string, info *service.ManagedCertInfo) {
	cmd.Printf("Certificate: %s\n", name)
	cmd.Printf("  Account: %s\n", info.Spec.Account)
	cmd.Printf("  Subject: %s\n", info.Certificate.Subject.CommonName)

	sans := collectSANs(info.Spec)
	if len(sans) > 0 {
		cmd.Printf("  SANs: %s\n", strings.Join(sans, ", "))
	}

	if info.Spec.Key != nil {
		keyDesc := info.Spec.Key.Algorithm
		if info.Spec.Key.ECC != nil && info.Spec.Key.ECC.Curve != "" {
			keyDesc += " " + info.Spec.Key.ECC.Curve
		}
		if info.Spec.Key.RSA != nil && info.Spec.Key.RSA.KeySize > 0 {
			cmd.Printf("  Key: %s %d (%s)\n", keyDesc, info.Spec.Key.RSA.KeySize, info.Spec.Key.Store)
		} else {
			cmd.Printf("  Key: %s (%s)\n", keyDesc, info.Spec.Key.Store)
		}
	}

	challenge := info.Spec.Challenge
	if challenge == "" {
		challenge = "http-01"
	}
	cmd.Printf("  Challenge: %s\n", challenge)
	cmd.Printf("  Status: issued\n")
	cmd.Printf("  Expires: %s\n", info.ExpiresAt.Format("2006-01-02"))

	if info.Spec.Renewal != nil {
		autoRenew := "no"
		if info.Spec.Renewal.Auto {
			cmd.Printf("  Auto-Renew: yes (%d days before)\n", info.Spec.Renewal.DaysBefore)
		} else {
			cmd.Printf("  Auto-Renew: %s\n", autoRenew)
		}
	}
}

// printUnissuedSpec prints information about a certificate spec that has not yet been issued.
func printUnissuedSpec(cmd *cobra.Command, name string, spec *service.CertificateSpec) {
	cmd.Printf("Certificate: %s (not yet issued)\n", name)
	cmd.Printf("  Account: %s\n", spec.Account)
	cmd.Printf("  Subject: %s\n", spec.Subject.CN)

	sans := collectSANs(spec)
	if len(sans) > 0 {
		cmd.Printf("  SANs: %s\n", strings.Join(sans, ", "))
	}

	if spec.Key != nil {
		keyDesc := spec.Key.Algorithm
		if spec.Key.ECC != nil && spec.Key.ECC.Curve != "" {
			keyDesc += " " + spec.Key.ECC.Curve
		}
		if spec.Key.RSA != nil && spec.Key.RSA.KeySize > 0 {
			cmd.Printf("  Key: %s %d (%s)\n", keyDesc, spec.Key.RSA.KeySize, spec.Key.Store)
		} else {
			cmd.Printf("  Key: %s (%s)\n", keyDesc, spec.Key.Store)
		}
	}

	challenge := spec.Challenge
	if challenge == "" {
		challenge = "http-01"
	}
	cmd.Printf("  Challenge: %s\n", challenge)
	cmd.Printf("  Status: pending\n")

	if spec.Renewal != nil {
		if spec.Renewal.Auto {
			cmd.Printf("  Auto-Renew: yes (%d days before)\n", spec.Renewal.DaysBefore)
		} else {
			cmd.Printf("  Auto-Renew: no\n")
		}
	}
}

// collectSANs gathers all SAN entries from a certificate spec into a single slice.
func collectSANs(spec *service.CertificateSpec) []string {
	var sans []string
	sans = append(sans, spec.SANs.DNS...)
	sans = append(sans, spec.SANs.IP...)
	sans = append(sans, spec.SANs.Email...)
	sans = append(sans, spec.SANs.URI...)
	return sans
}
