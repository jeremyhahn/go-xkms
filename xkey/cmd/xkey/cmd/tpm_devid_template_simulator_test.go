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

//go:build tpm_simulator

package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	gotpm2 "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireKeyOfTemplate asserts pub is the key the named template describes.
func requireKeyOfTemplate(t *testing.T, template string, pub crypto.PublicKey) {
	t.Helper()
	switch template {
	case "rsa2048", "rsa-pss":
		rsaPub, ok := pub.(*rsa.PublicKey)
		require.True(t, ok, "template %s must create an RSA key, got %T", template, pub)
		assert.Equal(t, 2048, rsaPub.N.BitLen())
	case "ecc256":
		eccPub, ok := pub.(*ecdsa.PublicKey)
		require.True(t, ok, "template %s must create an ECC key, got %T", template, pub)
		assert.Equal(t, elliptic.P256(), eccPub.Curve)
	default:
		t.Fatalf("unknown template %q", template)
	}
}

// TestRunIAKCreate_TemplateSelectsTheKey proves an explicit --template picks
// the IAK's algorithm and, for RSA, its signing scheme (TPMT_RSA_SCHEME of
// the restricted key's public area).
func TestRunIAKCreate_TemplateSelectsTheKey(t *testing.T) {
	schemes := map[string]gotpm2.TPMAlgID{
		"rsa2048": gotpm2.TPMAlgRSASSA,
		"rsa-pss": gotpm2.TPMAlgRSAPSS,
	}
	for _, template := range []string{"rsa2048", "rsa-pss", "ecc256"} {
		t.Run(template, func(t *testing.T) {
			sim := withProvisionedSimulatorTPM(t)
			setVar(t, &iakCreateForce, true)

			require.NoError(t, runWithTemplateFlag(t, runIAKCreate, &iakCreateTemplate, template))

			attrs, err := sim.tpm.IAKAttributes()
			require.NoError(t, err)
			pub, err := x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
			require.NoError(t, err)
			requireKeyOfTemplate(t, template, pub)

			if scheme, isRSA := schemes[template]; isRSA {
				rsaDetail, err := attrs.TPMAttributes.Public.Parameters.RSADetail()
				require.NoError(t, err)
				assert.Equal(t, scheme, rsaDetail.Scheme.Scheme)
			}
		})
	}
}

// TestRunIAKCreate_UnsetTemplateKeepsTheConfig proves the --template default
// does not override the configured IAK: an RSA-PSS key from the config.
func TestRunIAKCreate_UnsetTemplateKeepsTheConfig(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &iakCreateForce, true)
	setVar(t, &iakCreateTemplate, "ecc256")

	_, _, err := runTPMSubcommand(runIAKCreate)
	require.NoError(t, err)

	attrs, err := sim.tpm.IAKAttributes()
	require.NoError(t, err)
	pub, err := x509.ParsePKIXPublicKey(attrs.TPMAttributes.PublicKeyBytes)
	require.NoError(t, err)
	requireKeyOfTemplate(t, "rsa-pss", pub)
	rsaDetail, err := attrs.TPMAttributes.Public.Parameters.RSADetail()
	require.NoError(t, err)
	assert.Equal(t, gotpm2.TPMAlgRSAPSS, rsaDetail.Scheme.Scheme)
}

// TestRunIDevIDCreate_TemplateSelectsTheKey proves an explicit --template
// picks the IDevID's algorithm and the signature algorithm it signs with.
// An unrestricted IDevID's public area carries a NULL scheme (TCG "TPM 2.0
// Keys for Device Identity and Attestation", Template H-1), so the RSA
// padding is the key's configured signature algorithm.
func TestRunIDevIDCreate_TemplateSelectsTheKey(t *testing.T) {
	signatureAlgorithms := map[string]x509.SignatureAlgorithm{
		"rsa2048": x509.SHA256WithRSA,
		"rsa-pss": x509.SHA256WithRSAPSS,
		"ecc256":  x509.ECDSAWithSHA256,
	}
	for template, signatureAlgorithm := range signatureAlgorithms {
		t.Run(template, func(t *testing.T) {
			sim := withProvisionedSimulatorTPM(t)

			require.NoError(t, runWithTemplateFlag(t, runIDevIDCreate, &idevidCreateTemplate, template))

			pub, err := sim.tpm.IDevID()
			require.NoError(t, err)
			requireKeyOfTemplate(t, template, pub)

			attrs, err := sim.tpm.IDevIDAttributes()
			require.NoError(t, err)
			assert.Equal(t, signatureAlgorithm, attrs.SignatureAlgorithm)
		})
	}
}

// TestRunIDevIDCreate_UnsetTemplateKeepsTheConfig proves the --template
// default does not override the configured IDevID: an RSA key from the config.
func TestRunIDevIDCreate_UnsetTemplateKeepsTheConfig(t *testing.T) {
	sim := withProvisionedSimulatorTPM(t)
	setVar(t, &idevidCreateTemplate, "ecc256")

	_, _, err := runTPMSubcommand(runIDevIDCreate)
	require.NoError(t, err)

	pub, err := sim.tpm.IDevID()
	require.NoError(t, err)
	requireKeyOfTemplate(t, "rsa-pss", pub)
}
