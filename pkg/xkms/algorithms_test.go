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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestBuildAlgorithmsResponse_SoftwareOnly(t *testing.T) {
	backends := []BackendType{BackendSoftware}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true},
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
	expectedCurves := []string{"P-224", "P-256", "P-384", "P-521"}
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
		"software": {Keys: true},
		"tpm2":     {Keys: true, HardwareBacked: true},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	if len(resp.Signing) != 3 {
		t.Fatalf("expected 3 signing algorithms, got %d", len(resp.Signing))
	}

	assertAlgorithm(t, resp.Signing, "ECDSA", []string{"software", "tpm2"}, false)
	assertAlgorithm(t, resp.Signing, "RSA", []string{"software", "tpm2"}, false)
	assertAlgorithm(t, resp.Signing, "Ed25519", []string{"software", "tpm2"}, false)
}

func TestBuildAlgorithmsResponse_QuantumBackend(t *testing.T) {
	backends := []BackendType{BackendSoftware, BackendQuantum}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: true},
		"quantum":  {Keys: true, QuantumSigning: true, KeyEncapsulation: true},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	// 3 classical + 2 PQ signing
	if len(resp.Signing) != 5 {
		t.Fatalf("expected 5 signing algorithms, got %d", len(resp.Signing))
	}
	if len(resp.KeyEncapsulation) != 1 {
		t.Fatalf("expected 1 key encapsulation algorithm, got %d", len(resp.KeyEncapsulation))
	}

	assertAlgorithm(t, resp.Signing, "ML-DSA-65", []string{"quantum"}, true)
	assertAlgorithm(t, resp.Signing, "ML-DSA-87", []string{"quantum"}, true)
	assertAlgorithm(t, resp.KeyEncapsulation, "ML-KEM-1024", []string{"quantum"}, true)

	// Classical algorithms should only list software, not quantum (quantum has Keys:true so it also contributes)
	assertAlgorithm(t, resp.Signing, "ECDSA", []string{"software", "quantum"}, false)
}

func TestBuildAlgorithmsResponse_EmptyBackends(t *testing.T) {
	resp := BuildAlgorithmsResponse(nil, func(name string) (types.Capabilities, error) {
		return types.Capabilities{}, fmt.Errorf("no backend: %s", name)
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
			return types.Capabilities{Keys: true}, nil
		}
		return types.Capabilities{}, fmt.Errorf("backend unavailable: %s", name)
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
		"software": {Keys: true},
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

func TestBuildAlgorithmsResponse_NoKeysCapability(t *testing.T) {
	backends := []BackendType{BackendSoftware}
	provider := stubCapabilities(map[string]types.Capabilities{
		"software": {Keys: false, Signing: true},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	if len(resp.Signing) != 0 {
		t.Fatalf("expected 0 signing algorithms when Keys=false, got %d", len(resp.Signing))
	}
}

func TestBuildAlgorithmsResponse_QuantumSigningOnly(t *testing.T) {
	backends := []BackendType{BackendQuantum}
	provider := stubCapabilities(map[string]types.Capabilities{
		"quantum": {Keys: false, QuantumSigning: true, KeyEncapsulation: false},
	})

	resp := BuildAlgorithmsResponse(backends, provider)

	// No classical since Keys=false, but PQ signing should appear
	if len(resp.Signing) != 2 {
		t.Fatalf("expected 2 PQ signing algorithms, got %d", len(resp.Signing))
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
		"software": {Keys: true},
		"tpm2":     {Keys: true, HardwareBacked: true},
		"quantum":  {Keys: true, QuantumSigning: true, KeyEncapsulation: true},
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BuildAlgorithmsResponse(backends, provider)
	}
}

// stubCapabilities returns a CapabilitiesProvider backed by a static map.
func stubCapabilities(m map[string]types.Capabilities) CapabilitiesProvider {
	return func(name string) (types.Capabilities, error) {
		caps, ok := m[name]
		if !ok {
			return types.Capabilities{}, fmt.Errorf("unknown backend: %s", name)
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
