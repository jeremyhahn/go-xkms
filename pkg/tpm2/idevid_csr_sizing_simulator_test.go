//go:build tpm_simulator

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

package tpm2

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
)

// contentSizeFromPacked returns the true byte length of the packed
// TCG_IDEVID_CONTENT structure, derived independently of the Contents header
// the product writes. Asserting against this rather than a golden constant
// means the test states the TCG contract instead of restating the arithmetic
// under test.
func contentSizeFromPacked(t *testing.T, csr *TCG_CSR_IDEVID) int {
	t.Helper()
	packed, err := PackIDevIDContent(&csr.CsrContents)
	require.NoError(t, err)
	return len(packed)
}

// TestTCGCSR_ContentsHeader_MatchesPackedStructure is the interop regression
// test for the CSR size header.
//
// TCG "TPM 2.0 Keys for Device Identity and Attestation" section 13.1 defines
// Contents as the size of the TCG_IDEVID_CONTENT structure. A conformant CA
// slices the message by it. It used to be wrong three ways at once -- the
// payload sum omitted SigningPubSZ, SgnCertifyInfoSZ and
// SgnCertifyInfoSignatureSZ, the header count was 10 fields instead of 16, and
// the whole computation ran only when padding was enabled -- which understated
// a real CSR by roughly 709 bytes, or reported zero outright.
//
// Nothing inside xkms noticed because UnmarshalIDevIDCSR ignores Contents and
// re-reads the individual length fields. Only an external CA would have seen
// it, which is exactly why this needs pinning.
func TestTCGCSR_ContentsHeader_MatchesPackedStructure(t *testing.T) {
	for _, tc := range []struct {
		name string
		pad  bool
	}{
		{"padding disabled", false},
		{"padding enabled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSimHarness(t, func(c *Config) {
				c.IDevID = &IDevIDConfig{
					CN:                 "device-id-001",
					Hash:               crypto.SHA256.String(),
					Handle:             0x81020000,
					KeyAlgorithm:       x509.RSA.String(),
					Manufacturer:       "ATT",
					Model:              "xkms-test-device",
					Pad:                tc.pad,
					RSAConfig:          &store.RSAConfig{KeySize: 2048},
					Serial:             "SN-0000-0001",
					SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
				}
			})

			ekPub, err := h.TPM.EKRSA()
			require.NoError(t, err)
			ekCert := selfSignedCertForKey(t, ekPub)

			iakAttrs, err := h.TPM.IAKAttributes()
			require.NoError(t, err)

			csr, err := h.TPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, iakAttrs)
			require.NoError(t, err)

			declared := bytesToUint32(csr.Contents)
			actual := contentSizeFromPacked(t, &csr)

			require.NotZero(t, declared,
				"Contents must report the structure size, never zero")
			assert.Equal(t, actual, int(declared),
				"Contents must equal the packed TCG_IDEVID_CONTENT length")
		})
	}
}

// TestTCGCSR_PaddedStructure_Is16ByteAligned pins the other half of the TCG
// requirement: when padding is enabled the structure must be a multiple of 16
// bytes. The pad used to be computed as contents%16 -- the remainder rather
// than the complement -- so padded CSRs came out misaligned.
func TestTCGCSR_PaddedStructure_Is16ByteAligned(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			Pad:                true,
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)

	csr, err := h.TPM.CreateTCG_CSR_IDEVID(ekCert, iakAttrs, iakAttrs)
	require.NoError(t, err)

	size := contentSizeFromPacked(t, &csr)
	assert.Zero(t, size%16,
		"a padded TCG_IDEVID_CONTENT must be 16-byte aligned, got %d (%d mod 16)", size, size%16)

	padSz := bytesToUint32(csr.CsrContents.PadSz)
	assert.Less(t, padSz, uint32(16),
		"padding must be the complement to the next 16-byte boundary, so always < 16")
	assert.Len(t, csr.CsrContents.Pad, int(padSz),
		"the emitted pad must match the declared PadSz")
}

// TestTCGCSR_UnpaddedStructure_StillReportsItsSize guards the third defect
// specifically: with padding disabled the structure carries no pad, but
// Contents must still describe it. It previously stayed at its zero value
// because the whole computation lived inside the padding branch.
func TestTCGCSR_UnpaddedStructure_StillReportsItsSize(t *testing.T) {
	h := newCSRHarness(t)
	csr := buildDeviceCSR(t, h)

	require.Zero(t, bytesToUint32(csr.CsrContents.PadSz),
		"precondition: this harness disables padding")

	declared := bytesToUint32(csr.Contents)
	require.NotZero(t, declared, "an unpadded CSR must still report its size")
	assert.Equal(t, contentSizeFromPacked(t, csr), int(declared))
}

// TestReadPCRs_BankOrderIsDeterministic is the map-iteration regression test.
//
// ReadPCRs used to build its result by ranging over a map[string]TPMAlgID, so
// the order of the returned []PCRBank was randomized by the Go runtime on every
// call. Any caller indexing the slice -- banks[0] meaning "the SHA-1 bank" --
// read a different bank run to run. That is what actually broke
// TestPCRExtend_Simulator, whose failure was misattributed to test isolation
// and papered over with a "passes alone but fails in suite" skip guard.
//
// Repeated calls against one TPM must agree, and must match the documented
// order, so a caller reading the source can rely on it. Against the map version
// this fails within a few iterations.
func TestReadPCRs_BankOrderIsDeterministic(t *testing.T) {
	h := newSimHarness(t, nil)

	want := []string{"SHA1", "SHA256", "SHA384", "SHA512"}

	var reference []string
	for i := 0; i < 24; i++ {
		banks, err := h.TPM.ReadPCRs([]uint{0})
		require.NoError(t, err)

		order := make([]string, 0, len(banks))
		for _, b := range banks {
			order = append(order, b.Algorithm)
		}

		if reference == nil {
			reference = order
			continue
		}
		require.Equal(t, reference, order,
			"iteration %d: ReadPCRs returned banks in a different order", i)
	}

	assert.Equal(t, want, reference,
		"the bank order must be the documented one, not merely stable")
}

// TestReadPCRs_BankSelectedByAlgorithmNotIndex documents the safe way to use
// the result. Even with a deterministic order, matching on Algorithm is what
// callers should do; this asserts the field is populated and unique so that
// contract actually holds.
func TestReadPCRs_BankSelectedByAlgorithmNotIndex(t *testing.T) {
	h := newSimHarness(t, nil)

	banks, err := h.TPM.ReadPCRs([]uint{0, 7})
	require.NoError(t, err)
	require.NotEmpty(t, banks)

	seen := make(map[string]bool, len(banks))
	for _, b := range banks {
		require.NotEmpty(t, b.Algorithm, "every bank must name its algorithm")
		require.False(t, seen[b.Algorithm], "duplicate bank %q", b.Algorithm)
		seen[b.Algorithm] = true
		assert.NotEmpty(t, b.PCRs, "bank %q carried no PCR values", b.Algorithm)
	}
}
