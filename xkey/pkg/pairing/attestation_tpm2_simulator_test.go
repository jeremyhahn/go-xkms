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

package pairing

import (
	"bytes"
	"crypto/rand"
	"io"
	"log/slog"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLaptopAttestor_TPM2Attestation_QuotesTheNonce drives the TPM2 path of
// GenerateAttestation against the in-process simulator: the result must be a
// hardware quote over the default PCR selection that binds the caller's nonce,
// carries the EK certificate, and reports the boot hash of the quoted PCRs.
func TestLaptopAttestor_TPM2Attestation_QuotesTheNonce(t *testing.T) {
	tpm := enrollmentTPM(t)
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode:   AttestationModeTPM2,
		TPM:    tpm,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	nonce := make([]byte, attestationNonceSize)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	result, err := attestor.GenerateAttestation(nonce)
	require.NoError(t, err)

	assert.Equal(t, "tpm2", result.Format)
	assert.Equal(t, "hardware", result.SecurityLevel)
	assert.True(t, result.BootStateVerified)
	assert.Equal(t, nonce, result.Nonce)
	assert.True(t, bytes.Contains(result.QuoteData, nonce),
		"the quoted TPMS_ATTEST must carry the nonce as its extraData")
	assert.NotEmpty(t, result.QuoteSignature)

	ekCert, err := tpm.EKCertificate()
	require.NoError(t, err)
	assert.Contains(t, result.CertificateChain, ekCert.Raw)

	require.Len(t, result.PlatformPCRs, len(defaultAttestationPCRs))
	for _, idx := range defaultAttestationPCRs {
		value, ok := result.PlatformPCRs[int(idx)]
		require.True(t, ok, "PCR %d must be in the quote", idx)
		assert.Len(t, value, 32, "PCR %d must come from the SHA256 bank", idx)
	}
	assert.Equal(t, computeBootHash(result.PlatformPCRs), result.BootHashHex)
	assert.Regexp(t, regexp.MustCompile(`^\d+\.\d+$`), result.FirmwareVersion)
}

// TestLaptopAttestor_TPM2Attestation_QuoteFailure checks that a quote the TPM
// refuses (a PCR index outside the platform's banks) surfaces as
// ErrAttestationGenerationFailed rather than a partial result.
func TestLaptopAttestor_TPM2Attestation_QuoteFailure(t *testing.T) {
	attestor, err := NewLaptopAttestor(&LaptopAttestorConfig{
		Mode:   AttestationModeTPM2,
		TPM:    enrollmentTPM(t),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		PCRs:   []uint{4096},
	})
	require.NoError(t, err)

	result, err := attestor.GenerateAttestation(make([]byte, attestationNonceSize))
	require.ErrorIs(t, err, ErrAttestationGenerationFailed)
	assert.Nil(t, result)
}
