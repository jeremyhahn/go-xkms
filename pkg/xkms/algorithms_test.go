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

package xkms

import (
	"fmt"
	"slices"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAlgorithmsResponse_SoftwareOnly(t *testing.T) {
	backends := []BackendType{BackendSoftware}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true, KeyAlgorithms: classicalKeys},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	if len(resp.Signing) != 3 {
		t.Fatalf("expected 3 signing algorithms, got %d", len(resp.Signing))
	}
	if len(resp.KeyEncapsulation) != 0 {
		t.Fatalf("expected 0 key encapsulation algorithms, got %d", len(resp.KeyEncapsulation))
	}

	assertAlgorithm(t, resp.Signing, "ECDSA", []string{"software"}, false)
	assertAlgorithm(t, resp.Signing, "RSA", []string{"software"}, false)
	assertAlgorithm(t, resp.Signing, "Ed25519", []string{"software"}, false)

	// Verify ECDSA curves
	ecdsa := findAlgorithm(resp.Signing, "ECDSA")
	if ecdsa == nil {
		t.Fatal("ECDSA not found")
	}
	expectedCurves := []string{"P-256", "P-384", "P-521"}
	if len(ecdsa.Curves) != len(expectedCurves) {
		t.Fatalf("expected %d curves, got %d", len(expectedCurves), len(ecdsa.Curves))
	}
	for i, c := range expectedCurves {
		if ecdsa.Curves[i] != c {
			t.Errorf("curve[%d]: expected %s, got %s", i, c, ecdsa.Curves[i])
		}
	}

	// Verify RSA key sizes
	rsa := findAlgorithm(resp.Signing, "RSA")
	if rsa == nil {
		t.Fatal("RSA not found")
	}
	expectedSizes := []int{2048, 3072, 4096}
	if len(rsa.KeySizes) != len(expectedSizes) {
		t.Fatalf("expected %d key sizes, got %d", len(expectedSizes), len(rsa.KeySizes))
	}
	for i, s := range expectedSizes {
		if rsa.KeySizes[i] != s {
			t.Errorf("key_size[%d]: expected %d, got %d", i, s, rsa.KeySizes[i])
		}
	}
}

func TestBuildAlgorithmsResponse_SoftwareAndTPM2(t *testing.T) {
	backends := []BackendType{BackendSoftware, BackendTPM2}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true, KeyAlgorithms: classicalKeys},
		"tpm2":     {Keys: true, HardwareBacked: true, KeyAlgorithms: tpm2Keys},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	if len(resp.Signing) != 3 {
		t.Fatalf("expected 3 signing algorithms, got %d", len(resp.Signing))
	}

	assertAlgorithm(t, resp.Signing, "ECDSA", []string{"software", "tpm2"}, false)
	assertAlgorithm(t, resp.Signing, "RSA", []string{"software", "tpm2"}, false)
	// The TPM declares no Ed25519, so only the software backend offers it.
	assertAlgorithm(t, resp.Signing, "Ed25519", []string{"software"}, false)

	// Merged entries carry the union of the backends' sizes, once each.
	rsa := findAlgorithm(resp.Signing, "RSA")
	if !slices.Equal(rsa.KeySizes, []int{2048, 3072, 4096}) {
		t.Errorf("RSA key sizes = %v, want the union [2048 3072 4096]", rsa.KeySizes)
	}
}

func TestBuildAlgorithmsResponse_QuantumBackend(t *testing.T) {
	backends := []BackendType{BackendSoftware, BackendQuantum}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true, KeyAlgorithms: classicalKeys},
		"quantum":  {Keys: true, QuantumSigning: true, KeyEncapsulation: true, KeyAlgorithms: quantumKeys},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	// 3 classical + 3 ML-DSA parameter sets
	if len(resp.Signing) != 6 {
		t.Fatalf("expected 6 signing algorithms, got %d", len(resp.Signing))
	}
	if len(resp.KeyEncapsulation) != 2 {
		t.Fatalf("expected 2 key encapsulation algorithms, got %d", len(resp.KeyEncapsulation))
	}

	assertAlgorithm(t, resp.Signing, "ML-DSA-44", []string{"quantum"}, true)
	assertAlgorithm(t, resp.Signing, "ML-DSA-65", []string{"quantum"}, true)
	assertAlgorithm(t, resp.Signing, "ML-DSA-87", []string{"quantum"}, true)
	assertAlgorithm(t, resp.KeyEncapsulation, "ML-KEM-768", []string{"quantum"}, true)
	assertAlgorithm(t, resp.KeyEncapsulation, "ML-KEM-1024", []string{"quantum"}, true)

	// The quantum backend declares no classical keys.
	assertAlgorithm(t, resp.Signing, "ECDSA", []string{"software"}, false)
}

func TestBuildAlgorithmsResponse_EmptyBackends(t *testing.T) {
	resp := BuildAlgorithmsResponse(nil, func(name string) (types.Capabilities, error) {
		return types.Capabilities{}, &errs.Message{Msg: fmt.Sprintf("no backend: %s", name)}
	})

	if len(resp.Signing) != 0 {
		t.Fatalf("expected 0 signing algorithms, got %d", len(resp.Signing))
	}
	if len(resp.KeyEncapsulation) != 0 {
		t.Fatalf("expected 0 key encapsulation algorithms, got %d", len(resp.KeyEncapsulation))
	}
}

func TestBuildAlgorithmsResponse_CapabilitiesError(t *testing.T) {
	backends := []BackendType{BackendSoftware, BackendTPM2}
	provider := func(name string) (types.Capabilities, error) {
		if name == "software" {
			return types.Capabilities{Keys: true, KeyAlgorithms: classicalKeys}, nil
		}
		return types.Capabilities{}, &errs.Message{Msg: fmt.Sprintf("backend unavailable: %s", name)}
	}

	resp := BuildAlgorithmsResponse(backends, provider)

	// Only software should contribute since tpm2 returned an error
	if len(resp.Signing) != 3 {
		t.Fatalf("expected 3 signing algorithms, got %d", len(resp.Signing))
	}
	assertAlgorithm(t, resp.Signing, "ECDSA", []string{"software"}, false)
}

func TestBuildAlgorithmsResponse_SortOrder(t *testing.T) {
	backends := []BackendType{BackendSoftware}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true, KeyAlgorithms: classicalKeys},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	// Algorithms should be sorted alphabetically
	if len(resp.Signing) < 2 {
		t.Fatal("expected at least 2 signing algorithms for sort check")
	}
	for i := 1; i < len(resp.Signing); i++ {
		if resp.Signing[i].Algorithm < resp.Signing[i-1].Algorithm {
			t.Errorf("algorithms not sorted: %s before %s",
				resp.Signing[i-1].Algorithm, resp.Signing[i].Algorithm)
		}
	}
}

func TestBuildAlgorithmsResponse_FlagsWithoutDeclaration(t *testing.T) {
	backends := []BackendType{BackendSoftware}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true, Signing: true, QuantumSigning: true, KeyEncapsulation: true},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	// Capability flags alone advertise nothing: only declared algorithms are.
	if len(resp.Signing) != 0 || len(resp.KeyEncapsulation) != 0 {
		t.Fatalf("expected no algorithms without a declaration, got %+v", resp)
	}
}

func TestBuildAlgorithmsResponse_QuantumSigningOnly(t *testing.T) {
	backends := []BackendType{BackendQuantum}
	provider := stubCapabilities(map[string]types.Capabilities{
		"quantum": {QuantumSigning: true, KeyAlgorithms: types.KeyAlgorithms{MLDSA: quantumKeys.MLDSA}},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	// No classical keys and no ML-KEM declared, only the ML-DSA parameter sets.
	if len(resp.Signing) != 3 {
		t.Fatalf("expected 3 PQ signing algorithms, got %d", len(resp.Signing))
	}
	if len(resp.KeyEncapsulation) != 0 {
		t.Fatalf("expected 0 key encapsulation algorithms, got %d", len(resp.KeyEncapsulation))
	}
	assertAlgorithm(t, resp.Signing, "ML-DSA-65", []string{"quantum"}, true)
	assertAlgorithm(t, resp.Signing, "ML-DSA-87", []string{"quantum"}, true)
}

func BenchmarkBuildAlgorithmsResponse(b *testing.B) {
	backends := []BackendType{BackendSoftware, BackendTPM2, BackendQuantum}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true, KeyAlgorithms: classicalKeys},
		"tpm2":     {Keys: true, HardwareBacked: true, KeyAlgorithms: tpm2Keys},
		"quantum":  {Keys: true, QuantumSigning: true, KeyEncapsulation: true, KeyAlgorithms: quantumKeys},
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BuildAlgorithmsResponse(backends, provider)
	}
}

// stubCapabilities returns a CapabilitiesProvider backed by a static map.
// classicalKeys, tpm2Keys and quantumKeys are the key-algorithm declarations
// of the stub backends.
var (
	classicalKeys = types.KeyAlgorithms{
		RSAKeySizes: []int{types.RSAKeySize2048, types.RSAKeySize3072, types.RSAKeySize4096},
		ECDSACurves: []string{"P-256", "P-384", "P-521"},
		Ed25519:     true,
	}
	tpm2Keys = types.KeyAlgorithms{
		RSAKeySizes: []int{types.RSAKeySize2048},
		ECDSACurves: []string{"P-384", "P-256"},
	}
	quantumKeys = types.KeyAlgorithms{
		MLDSA: []types.QuantumAlgorithm{types.QuantumAlgorithmMLDSA44, types.QuantumAlgorithmMLDSA65, types.QuantumAlgorithmMLDSA87},
		MLKEM: []types.QuantumAlgorithm{types.QuantumAlgorithmMLKEM768, types.QuantumAlgorithmMLKEM1024},
	}
)

func stubCapabilities(m map[string]types.Capabilities) CapabilitiesProvider {
	return func(name string) (types.Capabilities, error) {
		caps, ok := m[name]
		if !ok {
			return types.Capabilities{}, &errs.Message{Msg: fmt.Sprintf("unknown backend: %s", name)}
		}
		return caps, nil
	}
}

// findAlgorithm returns the AlgorithmInfo with the given name, or nil.
func findAlgorithm(algos []types.AlgorithmInfo, name string) *types.AlgorithmInfo {
	for i := range algos {
		if algos[i].Algorithm == name {
			return &algos[i]
		}
	}
	return nil
}

// assertAlgorithm verifies that an algorithm exists in the slice with the
// expected backends and post-quantum flag.
func assertAlgorithm(t *testing.T, algos []types.AlgorithmInfo, name string, expectedBackends []string, postQuantum bool) {
	t.Helper()

	info := findAlgorithm(algos, name)
	if info == nil {
		t.Fatalf("algorithm %q not found", name)
	}

	if info.PostQuantum != postQuantum {
		t.Errorf("algorithm %q: expected post_quantum=%v, got %v", name, postQuantum, info.PostQuantum)
	}

	if len(info.Backends) != len(expectedBackends) {
		t.Fatalf("algorithm %q: expected %d backends %v, got %d %v",
			name, len(expectedBackends), expectedBackends, len(info.Backends), info.Backends)
	}

	for i, b := range expectedBackends {
		if info.Backends[i] != b {
			t.Errorf("algorithm %q backend[%d]: expected %s, got %s", name, i, b, info.Backends[i])
		}
	}
}

// ============================================================
// DiscoverAlgorithms — convenience wrapper over the compiled-in
// backend registry and the global capability provider.
// ============================================================

func TestDiscoverAlgorithms_NotInitialized(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	// No service configured: every compiled-in backend's capabilities lookup
	// fails with ErrNotInitialized, so the response must be non-nil with
	// empty lists rather than panicking.
	resp := DiscoverAlgorithms()
	require.NotNil(t, resp)
	assert.Empty(t, resp.Signing)
	assert.Empty(t, resp.KeyEncapsulation)
}

func TestDiscoverAlgorithms_WithConfiguredBackend(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	// Wire a real KeyProvider (not the nil-backend mockKeyStore) under the
	// "software" name so GetBackendCapabilities can call Capabilities()
	// without panicking on a nil interface, exercising the success path of
	// DiscoverAlgorithms end to end (SupportedBackends -> GetBackendCapabilities
	// -> BuildAlgorithmsResponse).
	software := newMockKeyStoreWithSealer("software", types.BackendTypeSoftware)
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": software},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	resp := DiscoverAlgorithms()
	require.NotNil(t, resp)

	// Confirm the capability lookup for the registered backend actually
	// succeeds (mockSealerBackend.Capabilities() returns a zero-value
	// Capabilities{}, so it contributes no algorithms, but must not error).
	caps, err := GetBackendCapabilities("software")
	require.NoError(t, err)
	assert.Equal(t, types.Capabilities{}, caps)
}
