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
	"os"
	"path/filepath"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/spf13/cobra"
)

// acmeEnrollChallenges are the device challenges `xkey acme enroll` accepts.
var acmeEnrollChallenges = map[string]bool{
	sdkacme.ACMEChallengeTypeEnroll01:       true,
	sdkacme.ACMEChallengeTypeEndorse01:      true,
	sdkacme.ACMEChallengeTypeDeviceAttest01: true,
}

// openACMETPMModuleFunc opens the local TPM as the ACME enrollment TPM
// module; the returned func releases it. Tests replace it with a stub.
var openACMETPMModuleFunc = openACMETPMModule

func openACMETPMModule(logger *slog.Logger, dataDir, device string, useSimulator bool) (sdkacme.ACMETPMModule, func() error, error) {
	dir, err := resolveDataDir(dataDir)
	if err != nil {
		return nil, nil, err
	}
	dev, err := openTPMWithKeyStore(logger, dir, device, useSimulator)
	if err != nil {
		return nil, nil, fmt.Errorf("acme: open tpm: %w", err)
	}
	return sdkacme.NewACMEXKMSTPMAdapter(dev.TPM(), dev.Keys()), dev.Close, nil
}

type acmeEnrollFlags struct {
	challenge  string
	ip         string
	port       string
	listenHost string
	commonName string
	pcrs       []int
	timeout    time.Duration
	dataDir    string
	tpmDevice  string
	simulator  bool
	outDir     string
}

func (f *acmeEnrollFlags) validate() error {
	if f.challenge == "" {
		return errors.New("acme: enroll needs --challenge")
	}
	if !acmeEnrollChallenges[f.challenge] {
		return fmt.Errorf("acme: unknown enroll challenge %q (want %s, %s or %s)", f.challenge,
			sdkacme.ACMEChallengeTypeEnroll01, sdkacme.ACMEChallengeTypeEndorse01, sdkacme.ACMEChallengeTypeDeviceAttest01)
	}
	if f.ip == "" && f.challenge != sdkacme.ACMEChallengeTypeDeviceAttest01 {
		return fmt.Errorf("acme: enroll challenge %s needs --ip", f.challenge)
	}
	return nil
}

func (f *acmeEnrollFlags) config(tpm sdkacme.ACMETPMModule) *sdkacme.ACMEEnrollmentConfig {
	return &sdkacme.ACMEEnrollmentConfig{
		Challenge:    f.challenge,
		IPAddress:    f.ip,
		TPMModule:    tpm,
		Port:         f.port,
		ListenHost:   f.listenHost,
		CommonName:   f.commonName,
		PCRSelection: f.pcrs,
		Timeout:      f.timeout,
	}
}

// writeEnrollment writes the enrolled certificates as PEM: one file each in
// outDir, or all of them to stdout when outDir is empty.
func writeEnrollment(c *cobra.Command, outDir string, res *sdkacme.ACMEEnrollmentResult) error {
	var chain [][]byte
	for _, cert := range res.Chain {
		chain = append(chain, cert.Raw)
	}
	parts := []struct {
		name string
		ders [][]byte
	}{
		{"idevid.pem", nil},
		{"iak.pem", nil},
		{"chain.pem", chain},
	}
	if res.IDevIDCertificate != nil {
		parts[0].ders = [][]byte{res.IDevIDCertificate.Raw}
	}
	if res.IAKCertificate != nil {
		parts[1].ders = [][]byte{res.IAKCertificate.Raw}
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			return fmt.Errorf("acme: out dir: %w", err)
		}
	}
	for _, p := range parts {
		if len(p.ders) == 0 {
			continue
		}
		path := ""
		if outDir != "" {
			path = filepath.Join(outDir, p.name)
		}
		if err := writePEMOutput(c.OutOrStdout(), path, p.ders...); err != nil {
			return err
		}
	}
	return nil
}

func newACMEEnrollCmd(flags *acmeFlags) *cobra.Command {
	ef := &acmeEnrollFlags{}
	c := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this device's TPM through an ACME device challenge",
		Long: `Enroll the local TPM with an ACME server using the enroll-01,
endorse-01 or device-attest-01 challenge, and write the issued IDevID, IAK
and chain certificates as PEM to --out-dir, or to stdout. No key material is
ever written.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := ef.validate(); err != nil {
				return err
			}
			tpm, release, err := openACMETPMModuleFunc(slog.Default(), ef.dataDir, ef.tpmDevice, ef.simulator)
			if err != nil {
				return err
			}
			defer func() { _ = release() }()
			return flags.withACMEClient(c, "", func(client acmeClient) error {
				res, err := client.EnrollDevice(c.Context(), ef.config(tpm))
				if err != nil {
					return fmt.Errorf("acme: enroll device: %w", err)
				}
				if res == nil {
					return errors.New("acme: enroll device: no result")
				}
				return writeEnrollment(c, ef.outDir, res)
			})
		},
	}
	fl := c.Flags()
	fl.StringVar(&ef.challenge, "challenge", "", "device challenge: enroll-01, endorse-01 or device-attest-01 (required)")
	fl.StringVar(&ef.ip, "ip", "", "device IP address the server validates (required unless device-attest-01)")
	fl.StringVar(&ef.port, "port", "8080", "port of the challenge listener")
	fl.StringVar(&ef.listenHost, "listen-host", "", "host the challenge listener binds")
	fl.StringVar(&ef.commonName, "common-name", "", "common name of the device certificate")
	fl.IntSliceVar(&ef.pcrs, "pcr", nil, "PCR indexes to attest (comma-separated)")
	fl.DurationVar(&ef.timeout, "timeout", 30*time.Second, "enrollment timeout")
	fl.StringVar(&ef.dataDir, "data-dir", "", "xkey data directory (TPM key store)")
	fl.StringVar(&ef.tpmDevice, "tpm-device", "", "TPM device path")
	fl.BoolVar(&ef.simulator, "tpm-simulator", false, "use the TPM simulator")
	fl.StringVar(&ef.outDir, "out-dir", "", "directory for idevid.pem, iak.pem and chain.pem (default stdout)")
	return c
}
