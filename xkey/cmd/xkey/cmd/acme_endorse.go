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
	"log/slog"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/spf13/cobra"
)

func newACMEEndorseCmd(flags *acmeFlags) *cobra.Command {
	ef := &acmeEnrollFlags{challenge: sdkacme.ACMEChallengeTypeEndorse01}
	var out string
	c := &cobra.Command{
		Use:   "endorse",
		Short: "Obtain an EK certificate for this device's TPM (endorse-01)",
		Long: `Request an endorsement key (EK) certificate for the local TPM from an
ACME server through the endorse-01 challenge, for TPMs that ship without a
manufacturer EK certificate. The certificate is written as PEM to --out, or to
stdout. No key material is ever written.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if ef.ip == "" {
				return errors.New("acme: --ip is required for endorse-01")
			}
			tpm, release, err := openACMETPMModuleFunc(slog.Default(), ef.dataDir, ef.tpmDevice, ef.simulator)
			if err != nil {
				return err
			}
			defer func() { _ = release() }()
			return flags.withACMEClient(c, "", func(client acmeClient) error {
				cert, err := client.RequestEndorsementKeyCertificate(c.Context(), ef.config(tpm))
				if err != nil {
					return fmt.Errorf("acme: endorse: %w", err)
				}
				if cert == nil {
					return errors.New("acme: endorse: no certificate")
				}
				return writePEMOutput(c.OutOrStdout(), out, cert.Raw)
			})
		},
	}
	fl := c.Flags()
	fl.StringVar(&ef.ip, "ip", "", "device IP address the server validates (required)")
	fl.StringVar(&ef.port, "port", "8080", "port of the challenge listener")
	fl.StringVar(&ef.listenHost, "listen-host", "", "host the challenge listener binds")
	fl.StringVar(&ef.commonName, "common-name", "", `common name of the EK certificate ("{cn}-ek", default "ek")`)
	fl.DurationVar(&ef.timeout, "timeout", 30*time.Second, "endorsement timeout")
	fl.StringVar(&ef.dataDir, "data-dir", "", "xkey data directory (TPM key store)")
	fl.StringVar(&ef.tpmDevice, "tpm-device", "", "TPM device path")
	fl.BoolVar(&ef.simulator, "tpm-simulator", false, "use the TPM simulator")
	fl.StringVar(&out, "out", "", "file for the EK certificate PEM (default stdout)")
	return c
}
