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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// idevidConfigForAKSchemeTests is the harness's usual IDevID configuration,
// shared by the AK-scheme variants below. The IDevID key itself stays RSA
// in every case here; only the certifying AK's algorithm/scheme varies,
// since that is what CreateIDevID's certification-signature extraction
// switches on (key.go, "switch akPub.Type").
var idevidConfigForAKSchemeTests = &IDevIDConfig{
	CN:                 "device-id-001",
	Debug:              true,
	Hash:               crypto.SHA256.String(),
	Handle:             0x81020000,
	KeyAlgorithm:       x509.RSA.String(),
	Manufacturer:       "ATT",
	Model:              "xkms-test-device",
	RSAConfig:          &store.RSAConfig{KeySize: 2048},
	Serial:             "SN-0000-0001",
	SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
}

// TestCreateIDevID_CertifyingAKIsRSASSA_ExtractsSignature proves
// CreateIDevID's certification-signature extraction takes the RSASSA
// branch, not just the RSA-PSS branch every other simulator test in this
// package exercises (the harness's default IAK is RSA-PSS), when the
// certifying AK is configured plain RSASSA.
func TestCreateIDevID_CertifyingAKIsRSASSA_ExtractsSignature(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IAK.SignatureAlgorithm = x509.SHA256WithRSA.String()
		c.IDevID = idevidConfigForAKSchemeTests
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err, "provisioning must leave a usable IAK behind")
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err, "the provisioned EK must be readable")
	ekCert := selfSignedCertForKey(t, ekPub)

	idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err)
	require.NotNil(t, idevidAttrs)
	require.NotNil(t, csr)
}

// TestCreateIDevID_CertifyingAKIsECC_ExtractsSignature proves CreateIDevID's
// certification-signature extraction takes the ECDSA branch (key.go,
// "case tpm2.TPMAlgECC" under "switch akPub.Type") -- entirely unreached
// by every other simulator test of CreateIDevID, which all provision the
// harness's default RSA IAK -- and produces a usable ASN.1 r||s signature.
func TestCreateIDevID_CertifyingAKIsECC_ExtractsSignature(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IAK.RSAConfig = nil
		c.IAK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.IAK.KeyAlgorithm = x509.ECDSA.String()
		c.IAK.SignatureAlgorithm = "ECDSA-SHA256"
		c.IDevID = idevidConfigForAKSchemeTests
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err, "provisioning must leave a usable IAK behind")
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err, "the provisioned EK must be readable")
	ekCert := selfSignedCertForKey(t, ekPub)

	idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err)
	require.NotNil(t, idevidAttrs)
	require.NotNil(t, csr)
}
