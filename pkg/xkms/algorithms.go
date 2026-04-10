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
	"sort"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// CapabilitiesProvider is the function signature for retrieving a backend's
// capabilities by name. This decouples the algorithm builder from the
// global service singleton so it can be tested in isolation.
type CapabilitiesProvider func(name string) (types.Capabilities, error)

// BuildAlgorithmsResponse inspects the given backends via the capabilities
// provider and returns an AlgorithmsResponse that describes every supported
// algorithm along with the backends that offer it.
//
// The function deduplicates algorithms by name: when multiple backends
// support the same algorithm, their identifiers are merged into a single
// AlgorithmInfo entry.
func BuildAlgorithmsResponse(
	backends []BackendType,
	getCapabilities CapabilitiesProvider,
) *types.AlgorithmsResponse {

	// signingMap and kemMap accumulate per-algorithm backend lists.
	signingMap := make(map[string]*types.AlgorithmInfo)
	kemMap := make(map[string]*types.AlgorithmInfo)

	for _, bt := range backends {
		name := string(bt)

		caps, err := getCapabilities(name)
		if err != nil {
			continue
		}

		if caps.Keys {
			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm: types.AlgorithmECDSA.String(),
				Curves: []string{
					types.CurveP224.String(),
					types.CurveP256.String(),
					types.CurveP384.String(),
					types.CurveP521.String(),
				},
			}, name)

			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm: types.AlgorithmRSA.String(),
				KeySizes: []int{
					types.RSAKeySize2048,
					types.RSAKeySize3072,
					types.RSAKeySize4096,
				},
			}, name)

			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm: types.AlgorithmEd25519.String(),
			}, name)
		}

		if caps.QuantumSigning {
			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm:   "ML-DSA-65",
				PostQuantum: true,
			}, name)

			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm:   "ML-DSA-87",
				PostQuantum: true,
			}, name)
		}

		if caps.KeyEncapsulation {
			mergeAlgorithm(kemMap, types.AlgorithmInfo{
				Algorithm:   "ML-KEM-1024",
				PostQuantum: true,
			}, name)
		}
	}

	return &types.AlgorithmsResponse{
		Signing:          sortedAlgorithms(signingMap),
		KeyEncapsulation: sortedAlgorithms(kemMap),
	}
}

// mergeAlgorithm adds the backend name to an existing entry in the map, or
// creates a new entry if one does not yet exist.
func mergeAlgorithm(m map[string]*types.AlgorithmInfo, info types.AlgorithmInfo, backend string) {
	existing, ok := m[info.Algorithm]
	if !ok {
		info.Backends = []string{backend}
		m[info.Algorithm] = &info
		return
	}
	existing.Backends = append(existing.Backends, backend)
}

// sortedAlgorithms converts the map values to a sorted slice for
// deterministic JSON output.
func sortedAlgorithms(m map[string]*types.AlgorithmInfo) []types.AlgorithmInfo {
	result := make([]types.AlgorithmInfo, 0, len(m))
	for _, info := range m {
		result = append(result, *info)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Algorithm < result[j].Algorithm
	})
	return result
}

// DiscoverAlgorithms is a convenience wrapper that uses the compiled-in
// backend registry and the global GetBackendCapabilities function.
func DiscoverAlgorithms() *types.AlgorithmsResponse {
	return BuildAlgorithmsResponse(SupportedBackends(), GetBackendCapabilities)
}
