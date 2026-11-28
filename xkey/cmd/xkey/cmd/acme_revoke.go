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
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/spf13/cobra"
)

// parseRevocationReason and loadCertificatePEM are shared with the GUI
// ACMEService.
var (
	parseRevocationReason = services.ParseACMERevocationReason
	loadCertificatePEM    = services.LoadCertificatePEM
)

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
