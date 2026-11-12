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

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme"
)

// acmeRevocationReasons maps RFC 5280 5.3.1 reason names to codes.
var acmeRevocationReasons = map[string]acme.CRLReasonCode{
	"unspecified":          acme.CRLReasonUnspecified,
	"keyCompromise":        acme.CRLReasonKeyCompromise,
	"caCompromise":         acme.CRLReasonCACompromise,
	"affiliationChanged":   acme.CRLReasonAffiliationChanged,
	"superseded":           acme.CRLReasonSuperseded,
	"cessationOfOperation": acme.CRLReasonCessationOfOperation,
	"certificateHold":      acme.CRLReasonCertificateHold,
	"removeFromCRL":        acme.CRLReasonRemoveFromCRL,
	"privilegeWithdrawn":   acme.CRLReasonPrivilegeWithdrawn,
	"aACompromise":         acme.CRLReasonAACompromise,
}

// parseRevocationReason accepts a reason name or its number (7 is unused
// in RFC 5280).
func parseRevocationReason(s string) (acme.CRLReasonCode, error) {
	if code, ok := acmeRevocationReasons[s]; ok {
		return code, nil
	}
	n, err := strconv.Atoi(s)
	if err == nil && n >= int(acme.CRLReasonUnspecified) && n <= int(acme.CRLReasonAACompromise) && n != 7 {
		return acme.CRLReasonCode(n), nil
	}
	return 0, fmt.Errorf("acme: unknown revocation reason %q", s)
}

// loadCertificatePEM reads the first certificate of a PEM file.
func loadCertificatePEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("acme: certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("acme: %s holds no PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("acme: certificate %s: %w", path, err)
	}
	return cert, nil
}

func newACMERevokeCmd(flags *acmeFlags) *cobra.Command {
	var certFile, reason string
	c := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate issued to the ACME account",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if certFile == "" {
				return errors.New("acme: revoke needs --cert")
			}
			code, err := parseRevocationReason(reason)
			if err != nil {
				return err
			}
			cert, err := loadCertificatePEM(certFile)
			if err != nil {
				return err
			}
			return flags.withACMEClient(c, "", func(client acmeClient) error {
				if err := client.RevokeCertificate(c.Context(), cert, code); err != nil {
					return fmt.Errorf("acme: revoke certificate: %w", err)
				}
				_, _ = fmt.Fprintf(c.OutOrStdout(), "revoked certificate serial %s (reason %d)\n", cert.SerialNumber.Text(16), code)
				return nil
			})
		},
	}
	c.Flags().StringVar(&certFile, "cert", "", "PEM certificate to revoke (required)")
	c.Flags().StringVar(&reason, "reason", "unspecified", "RFC 5280 revocation reason name or number")
	return c
}
