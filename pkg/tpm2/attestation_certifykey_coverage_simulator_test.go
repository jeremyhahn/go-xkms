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

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestCertifyKey_TransientKey_EveryCommandFailurePropagates sweeps
// CertifyKey's full command sequence for a transient key: LoadKeyPair's own
// primary-load round trip, the target key's ReadPublic once it is loaded,
// TPM2_Certify itself, the IAK's ReadPublic to learn its signing scheme,
// and the deferred flush of the loaded transient key. It proves a failure
// at any of those round trips -- in particular the target-key ReadPublic
// that runs immediately after LoadKeyPair succeeds -- surfaces as an error
// instead of CertifyKey returning a CertifyResult built on a key it never
// actually confirmed was loaded.
func TestCertifyKey_TransientKey_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)

		srkAttrs, err := h.TPM.SSRKAttributes()
		require.NoError(t, err)

		keyAttrs := &types.KeyAttributes{
			CN:                 "transient-certified-key",
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeTLS,
			SignatureAlgorithm: x509.SHA256WithRSA,
			Parent:             srkAttrs,
			StoreType:          types.StoreTPM2,
			TPMAttributes:      &types.TPMAttributes{Hierarchy: tpm2.TPMRHOwner},
		}
		_, err = h.TPM.CreateRSA(keyAttrs, h.Backend, true)
		require.NoError(t, err)
		h.TPM.Flush(keyAttrs.TPMAttributes.Handle)
		// Reset the handle so CertifyKey takes the transient/load branch.
		keyAttrs.TPMAttributes.Handle = 0

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.CertifyKey(keyAttrs, []byte("transient-sweep-nonce"), h.Backend)
			return err
		}
	},
		// The last command is CertifyKey's own deferred best-effort flush of
		// the transient key's loaded handle (defer tpm.Flush(loadResp.ObjectHandle),
		// registered right after LoadKeyPair succeeds); like every other
		// tpm.Flush call in this package it logs a failure instead of
		// returning it, and a defer always runs last.
		5)
}

// TestCertifyKey_RSAUnionMismatch_RSASSAAgainstActualPSSSignature proves
// CertifyKey checks the TPMU_SIGNATURE union tag it extracts against, not
// just the IAK's declared SignatureAlgorithm. The default harness IAK signs
// with RSA-PSS (its real TPM key template), so mutating the cached
// tpm.iakAttrs.SignatureAlgorithm to a non-PSS value after the key was
// created forces CertifyKey down the RSASSA() extraction branch against a
// TPMS_ATTEST signature that is actually RSA-PSS -- a union mismatch that
// must surface as an error, not a silently wrong or empty signature.
func TestCertifyKey_RSAUnionMismatch_RSASSAAgainstActualPSSSignature(t *testing.T) {
	h := newSimHarness(t, nil) // newSimConfig's IAK is configured RSA-PSS.

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	require.NotNil(t, h.TPM.iakAttrs, "provisioning must leave a usable cached IAK behind")
	h.TPM.iakAttrs.SignatureAlgorithm = x509.SHA256WithRSA // Force the RSASSA() extraction branch.

	result, err := h.TPM.CertifyKey(srkAttrs, []byte("union-mismatch-nonce-1"), h.Backend)
	require.Error(t, err, "extracting an RSASSA signature from an actual RSA-PSS TPMS_ATTEST must fail")
	require.Nil(t, result)
}

// TestCertifyKey_RSAUnionMismatch_PSSAgainstActualSSASignature is the mirror
// of TestCertifyKey_RSAUnionMismatch_RSASSAAgainstActualPSSSignature: an IAK
// provisioned with a plain RSASSA key template, whose cached
// SignatureAlgorithm is then mutated to a PSS variant, must fail extracting
// RSAPSS() from a TPMS_ATTEST signature that is actually RSASSA.
func TestCertifyKey_RSAUnionMismatch_PSSAgainstActualSSASignature(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IAK.SignatureAlgorithm = x509.SHA256WithRSA.String()
	})

	srkAttrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)

	require.NotNil(t, h.TPM.iakAttrs, "provisioning must leave a usable cached IAK behind")
	h.TPM.iakAttrs.SignatureAlgorithm = x509.SHA256WithRSAPSS // Force the RSAPSS() extraction branch.

	result, err := h.TPM.CertifyKey(srkAttrs, []byte("union-mismatch-nonce-2"), h.Backend)
	require.Error(t, err, "extracting an RSA-PSS signature from an actual RSASSA TPMS_ATTEST must fail")
	require.Nil(t, result)
}
