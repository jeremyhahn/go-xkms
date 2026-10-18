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

package cmd

import (
	"crypto/x509"

	"github.com/spf13/cobra"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// devidTemplate is the crypto suite one --template value of
// `xkey tpm iak create` and `xkey tpm idevid create` selects.
type devidTemplate struct {
	keyAlgorithm       x509.PublicKeyAlgorithm
	signatureAlgorithm x509.SignatureAlgorithm
	rsaKeySize         int
	eccCurve           string
}

// devidTemplates maps each --template value onto the TCG "TPM 2.0 Keys for
// Device Identity and Attestation" v1.00 r12, section 7.3.4 templates the
// configuration path builds: H-1 (RSA 2048) for rsa2048 and rsa-pss, H-2
// (ECC NIST P-256) for ecc256. The two RSA values differ in the signature
// scheme only: RSASSA-PKCS1-v1_5 or RSASSA-PSS.
var devidTemplates = map[string]devidTemplate{
	"rsa2048": {keyAlgorithm: x509.RSA, signatureAlgorithm: x509.SHA256WithRSA, rsaKeySize: 2048},
	"rsa-pss": {keyAlgorithm: x509.RSA, signatureAlgorithm: x509.SHA256WithRSAPSS, rsaKeySize: 2048},
	"ecc256":  {keyAlgorithm: x509.ECDSA, signatureAlgorithm: x509.ECDSAWithSHA256, eccCurve: "P-256"},
}

// explicitDevIDTemplate returns the suite of the --template value when the
// user set the flag. It returns nil when the flag was left at its default,
// so the configuration decides.
func explicitDevIDTemplate(cmd *cobra.Command, name string) *devidTemplate {
	if !cmd.Flags().Changed("template") {
		return nil
	}
	template := devidTemplates[name]
	return &template
}

// applyIAK sets the IAK configuration's suite to the template's.
func (d *devidTemplate) applyIAK(config *xkms.IAKConfig) {
	if config == nil {
		return
	}
	config.KeyAlgorithm = d.keyAlgorithm.String()
	config.SignatureAlgorithm = d.signatureAlgorithm.String()
	config.RSAConfig, config.ECCConfig = d.keyConfigs()
}

// applyIDevID sets the IDevID configuration's suite to the template's.
func (d *devidTemplate) applyIDevID(config *xkms.IDevIDConfig) {
	if config == nil {
		return
	}
	config.KeyAlgorithm = d.keyAlgorithm.String()
	config.SignatureAlgorithm = d.signatureAlgorithm.String()
	config.RSAConfig, config.ECCConfig = d.keyConfigs()
}

// keyConfigs returns the RSA or ECC key configuration of the template; the
// other one is nil.
func (d *devidTemplate) keyConfigs() (*xkms.RSAConfig, *xkms.ECCConfig) {
	if d.keyAlgorithm == x509.ECDSA {
		return nil, &xkms.ECCConfig{Curve: d.eccCurve}
	}
	return &xkms.RSAConfig{KeySize: d.rsaKeySize}, nil
}
