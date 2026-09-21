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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- backendPIVKeyGenerator.AttestLevel ---

// TestBackendGenerator_AttestLevel_SoftwareBackend proves a backend whose
// KeyProvider reports HardwareBacked=false classifies as
// types.AttestLevelSoftware — the everyday case, since the real software
// backend (pkg/backend/software) is what every existing PIV test in this
// file runs against.
func TestBackendGenerator_AttestLevel_SoftwareBackend(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StoreSoftware)

	level, err := gen.AttestLevel(pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, types.AttestLevelSoftware, level)
}

// TestBackendGenerator_AttestLevel_HardwareBackend proves a backend whose
// KeyProvider reports HardwareBacked=true classifies as
// types.AttestLevelHardware, using the same Capabilities signal the backend
// catalog and UI sorting already read (types.Capabilities.HardwareBacked) —
// PIV does not invent a second classification.
func TestBackendGenerator_AttestLevel_HardwareBackend(t *testing.T) {
	provider := mocks.NewMockBackend()
	provider.CapabilitiesFunc = func() types.Capabilities {
		return types.Capabilities{HardwareBacked: true}
	}
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StorePKCS11)

	level, err := gen.AttestLevel(pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "piv-9a")
	require.NoError(t, err)
	assert.Equal(t, types.AttestLevelHardware, level)
}

// --- softwarePIVKeyGenerator.AttestLevel ---

// TestSoftwareGenerator_AttestLevel_AlwaysSoftware proves the fallback
// generator always reports types.AttestLevelSoftware, both for a CN it has
// never seen and one it holds a key for — its classification is a property
// of the generator, not of any specific key.
func TestSoftwareGenerator_AttestLevel_AlwaysSoftware(t *testing.T) {
	gen := NewSoftwarePIVKeyGenerator()
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)

	level, err := gen.AttestLevel(slot, "never-seen")
	require.NoError(t, err)
	assert.Equal(t, types.AttestLevelSoftware, level)

	_, genErr := gen.GeneratePIVKey(slot, "ecdsap256", "generated-cn")
	require.NoError(t, genErr)

	level, err = gen.AttestLevel(slot, "generated-cn")
	require.NoError(t, err)
	assert.Equal(t, types.AttestLevelSoftware, level)
}

// --- pivAttestLevel: the generic fallback used at enrollment time ---

// attestLevelStubGenerator is a bare PIVKeyGenerator with no
// PIVAttestLevelReporter capability, standing in for a caller-supplied
// generator (e.g. AdminEnrollmentConfig.PIVGenerator) that cannot back any
// claim about its hardware backing.
type attestLevelStubGenerator struct{}

func (attestLevelStubGenerator) GeneratePIVKey(pivcert.PIVSlot, string, string) (crypto.Signer, error) {
	return nil, ErrPIVInvalidAlgorithm
}

func (attestLevelStubGenerator) GetPIVSigner(pivcert.PIVSlot, string) (crypto.Signer, error) {
	return nil, ErrPIVSignerNotAvailable
}

var _ PIVKeyGenerator = attestLevelStubGenerator{}

// attestLevelReportingGenerator is a PIVKeyGenerator that also implements
// PIVAttestLevelReporter, returning a fixed level or error for assertions.
type attestLevelReportingGenerator struct {
	attestLevelStubGenerator
	level types.AttestLevel
	err   error
}

func (g attestLevelReportingGenerator) AttestLevel(pivcert.PIVSlot, string) (types.AttestLevel, error) {
	return g.level, g.err
}

var _ PIVAttestLevelReporter = attestLevelReportingGenerator{}

func TestPivAttestLevel_NoCapability_ReportsUnattested(t *testing.T) {
	level := pivAttestLevel(attestLevelStubGenerator{}, pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "cn")
	assert.Equal(t, types.AttestLevelUnattested, level)
}

func TestPivAttestLevel_WithCapability_UsesReportedLevel(t *testing.T) {
	tests := []struct {
		name  string
		level types.AttestLevel
	}{
		{"hardware", types.AttestLevelHardware},
		{"software", types.AttestLevelSoftware},
		{"unattested", types.AttestLevelUnattested},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := attestLevelReportingGenerator{level: tt.level}
			level := pivAttestLevel(gen, pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "cn")
			assert.Equal(t, tt.level, level)
		})
	}
}

// TestPivAttestLevel_ReporterError_FailsToUnattested proves a reporter that
// tried to answer and could not still leaves the key unattested rather than
// enrolled with a guess.
func TestPivAttestLevel_ReporterError_FailsToUnattested(t *testing.T) {
	gen := attestLevelReportingGenerator{level: types.AttestLevelHardware, err: errors.New("attestation query failed")}
	level := pivAttestLevel(gen, pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "cn")
	assert.Equal(t, types.AttestLevelUnattested, level)
}

// --- Enrollment: GeneratePIVKey/ImportPIVKey record the level next to KeyOrigin ---

// TestGeneratePIVKey_RecordsAttestLevel_Hardware proves a hardware-backed
// generator's GeneratePIVKey stamps types.AttestLevelHardware onto the
// KeyAttributes it hands the backend to generate, alongside KeyOrigin.
//
// This uses mockXKMSBackend, which records the exact attrs GeneratePIVKey
// passed to GenerateECDSA, rather than a real backend's ListKeys — a mock
// key provider's ListKeys does not round-trip these fields (nothing asks it
// to), so asserting through it here would test the mock's plumbing rather
// than backendPIVKeyGenerator's. TestGeneratePIVKey_RecordsAttestLevel_Software
// and TestImportPIVKey_RecordsAttestLevel below cover the real,
// software-backed round trip end to end.
func TestGeneratePIVKey_RecordsAttestLevel_Hardware(t *testing.T) {
	signer := newTestECDSASigner(t)
	mock := &mockXKMSBackend{
		hardwareBacked: true,
		generateECDSAFunc: func(*types.KeyAttributes) (crypto.PrivateKey, error) {
			return signer, nil
		},
		signerFunc: func(*types.KeyAttributes) (crypto.Signer, error) {
			return signer, nil
		},
	}
	gen := newBackendPIVKeyGenerator(mock, types.StorePKCS11)
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	_, err := gen.GeneratePIVKey(slot, "ecdsap256", cn)
	require.NoError(t, err)

	require.Len(t, mock.generateCalls, 1)
	assert.Equal(t, types.AttestLevelHardware, mock.generateCalls[0].AttestLevel)
	assert.Equal(t, types.KeyOriginGenerated, mock.generateCalls[0].KeyOrigin, "KeyOrigin and AttestLevel are siblings, recorded together")
}

// TestGeneratePIVKey_RecordsAttestLevel_Software is the software-backend
// companion: the same enrollment path records types.AttestLevelSoftware
// rather than defaulting to hardware or leaving the field unset.
func TestGeneratePIVKey_RecordsAttestLevel_Software(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StoreSoftware)
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	_, err = gen.GeneratePIVKey(slot, "ecdsap256", cn)
	require.NoError(t, err)

	keys, err := realBackend.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, types.AttestLevelSoftware, keys[0].AttestLevel)
}

// TestImportPIVKey_RecordsAttestLevel proves the import path records the
// same level a generate would for the identical backend — AttestLevel
// answers where the key lives, not how it arrived, so KeyOrigin differing
// between the two paths must not change it.
func TestImportPIVKey_RecordsAttestLevel(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	realBackend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	gen := newBackendPIVKeyGenerator(realBackend, types.StoreSoftware)
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)
	cn := PivSlotCN(slot)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = gen.ImportPIVKey(context.Background(), slot, "ecdsap256", cn, key)
	require.NoError(t, err)

	keys, err := realBackend.ListKeys(context.Background())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, types.AttestLevelSoftware, keys[0].AttestLevel)
	assert.Equal(t, types.KeyOriginImported, keys[0].KeyOrigin)
}
