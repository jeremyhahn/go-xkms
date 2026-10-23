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
	"cmp"
	"slices"
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
// Each backend contributes the signing and key-encapsulation algorithms its
// Capabilities.KeyAlgorithms declares, the same declaration
// GetSupportedAlgorithms reads, so the two never disagree. The function
// deduplicates algorithms by name: when multiple backends support the same
// algorithm, their identifiers, curves and key sizes are merged into a single
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
		declared := caps.KeyAlgorithms

		if len(declared.ECDSACurves) > 0 {
			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm: types.AlgorithmECDSA.String(),
				Curves:    declared.ECDSACurves,
			}, name)
		}
		if len(declared.RSAKeySizes) > 0 {
			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm: types.AlgorithmRSA.String(),
				KeySizes:  declared.RSAKeySizes,
			}, name)
		}
		if declared.Ed25519 {
			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm: types.AlgorithmEd25519.String(),
			}, name)
		}
		for _, parameterSet := range declared.MLDSA {
			mergeAlgorithm(signingMap, types.AlgorithmInfo{
				Algorithm:   string(parameterSet),
				PostQuantum: true,
			}, name)
		}
		for _, parameterSet := range declared.MLKEM {
			mergeAlgorithm(kemMap, types.AlgorithmInfo{
				Algorithm:   string(parameterSet),
				PostQuantum: true,
			}, name)
		}
	}

	return &types.AlgorithmsResponse{
		Signing:          sortedAlgorithms(signingMap),
		KeyEncapsulation: sortedAlgorithms(kemMap),
	}
}

// mergeAlgorithm adds the backend name, curves and key sizes to an existing
// entry in the map, or creates a new entry if one does not yet exist.
func mergeAlgorithm(m map[string]*types.AlgorithmInfo, info types.AlgorithmInfo, backend string) {
	existing, ok := m[info.Algorithm]
	if !ok {
		info.Curves = slices.Sorted(slices.Values(info.Curves))
		info.KeySizes = slices.Sorted(slices.Values(info.KeySizes))
		info.Backends = []string{backend}
		m[info.Algorithm] = &info
		return
	}
	existing.Curves = sortedUnion(existing.Curves, info.Curves)
	existing.KeySizes = sortedUnion(existing.KeySizes, info.KeySizes)
	existing.Backends = append(existing.Backends, backend)
}

// sortedUnion returns the sorted union of a and b, each value once.
func sortedUnion[T cmp.Ordered](a, b []T) []T {
	return slices.Compact(slices.Sorted(slices.Values(slices.Concat(a, b))))
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
