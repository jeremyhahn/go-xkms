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
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/spf13/cobra"
)

// writeCertificatesPEM writes each certificate as a PEM CERTIFICATE block.
func writeCertificatesPEM(w io.Writer, ders ...[]byte) error {
	for _, der := range ders {
		if _, err := w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
	}
	return nil
}

// writePEMOutput writes certificates to path, or to w when path is empty.
func writePEMOutput(w io.Writer, path string, ders ...[]byte) error {
	if path == "" {
		return writeCertificatesPEM(w, ders...)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) // #nosec G304 G302 -- operator-supplied path, public certificate
	if err != nil {
		return fmt.Errorf("acme: write %s: %w", path, err)
	}
	if err := writeCertificatesPEM(f, ders...); err != nil {
		_ = f.Close()
		return fmt.Errorf("acme: write %s: %w", path, err)
	}
	return f.Close()
}

func newACMERenewCmd(flags *acmeFlags) *cobra.Command {
	var certFile, csrFile, domain, authzType, challenge, out string
	c := &cobra.Command{
		Use:   "renew",
		Short: "Renew a certificate through the ACME account",
		Long: `Request a new certificate for the identifier of an existing one.

The renewed certificate is written as PEM to --out, or to stdout. No key
material is ever written.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if certFile == "" {
				return errors.New("acme: renew needs --cert")
			}
			if domain == "" {
				return errors.New("acme: renew needs --domain")
			}
			oldCert, err := loadCertificatePEM(certFile)
			if err != nil {
				return err
			}
			req := &sdkacme.ACMECertificateRequest{
				AuthzType:     authzType,
				AuthzValue:    domain,
				ChallengeType: challenge,
			}
			if csrFile != "" {
				if req.CSR, err = services.LoadACMECSR(csrFile); err != nil {
					return err
				}
			}
			return flags.withACMEClient(c, "", func(client acmeClient) error {
				cert, err := client.RenewCertificate(c.Context(), oldCert, req)
				if err != nil {
					return fmt.Errorf("acme: renew certificate: %w", err)
				}
				if cert == nil {
					return errors.New("acme: renew certificate: server returned no certificate")
				}
				return writePEMOutput(c.OutOrStdout(), out, cert.Raw)
			})
		},
	}
	c.Flags().StringVar(&certFile, "cert", "", "PEM certificate to renew (required)")
	c.Flags().StringVar(&domain, "domain", "", "identifier value to authorize (required)")
	c.Flags().StringVar(&authzType, "authz-type", "dns", "identifier type: dns, ip or permanent-identifier")
	c.Flags().StringVar(&challenge, "challenge", "", "challenge type (client default when empty)")
	c.Flags().StringVar(&csrFile, "csr", "", "PEM or DER certificate signing request")
	c.Flags().StringVar(&out, "out", "", "file for the renewed PEM certificate (default stdout)")
	return c
}
