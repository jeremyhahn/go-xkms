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
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/require"
)

// TestVerifyTCG_CSR_IAK_Stateless_ValidCSR_Succeeds proves the success path
// of the single-key (EnrollmentStrategyIAK) stateless verifier: a CSR a real
// TPM produced, self-signed by its IAK, must verify and yield the IAK's
// public key. Every other existing test of this function stops at an early
// rejection (bad hash bounds, wrong attributes, unsupported key type); this
// is the one path a real CA's success case actually takes.
func TestVerifyTCG_CSR_IAK_Stateless_ValidCSR_Succeeds(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	pubKey, unpacked, err := VerifyTCG_CSR_IAK_Stateless(csr, x509.SHA256WithRSAPSS)
	require.NoError(t, err)
	require.NotNil(t, pubKey, "a successful verification must return the IAK's public key")
	require.NotNil(t, unpacked)
}

// TestVerifyTCG_CSR_IAK_Stateless_ECDSAKey_Succeeds proves the function's
// ECDSA branch (tpm2.TPMAlgECC case), which every other existing test of
// this function skips -- they all provision the harness's default RSA IAK.
func TestVerifyTCG_CSR_IAK_Stateless_ECDSAKey_Succeeds(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IAK.RSAConfig = nil
		c.IAK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.IAK.KeyAlgorithm = x509.ECDSA.String()
		c.IAK.SignatureAlgorithm = "ECDSA-SHA256"
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Hash:               "SHA-256",
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                false,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	csr, err := h.TPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, iakAttrs)
	require.NoError(t, err)

	pubKey, unpacked, err := VerifyTCG_CSR_IAK_Stateless(&csr, x509.ECDSAWithSHA256)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.NotNil(t, unpacked)
}
