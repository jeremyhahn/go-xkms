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
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// softwareAlgorithms is everything the software backend declares.
var softwareAlgorithms = []transport.KeyAlgorithm{
	transport.KeyAlgorithmRSA2048, transport.KeyAlgorithmRSA3072, transport.KeyAlgorithmRSA4096,
	transport.KeyAlgorithmECDSAP256, transport.KeyAlgorithmECDSAP384, transport.KeyAlgorithmECDSAP521,
	transport.KeyAlgorithmEd25519, transport.KeyAlgorithmX25519,
	transport.KeyAlgorithmAES128GCM, transport.KeyAlgorithmAES192GCM, transport.KeyAlgorithmAES256GCM,
	transport.KeyAlgorithmChaCha20Poly1305, transport.KeyAlgorithmXChaCha20Poly1305,
	transport.KeyAlgorithmHMACSHA256, transport.KeyAlgorithmHMACSHA384, transport.KeyAlgorithmHMACSHA512,
}

// fipsApproved returns algorithms without the ones FIPS 140-3 does not
// approve.
func fipsApproved(algorithms []transport.KeyAlgorithm) []transport.KeyAlgorithm {
	var approved []transport.KeyAlgorithm
	for _, algorithm := range algorithms {
		if !fipsUnapprovedKeyAlgorithms[algorithm] {
			approved = append(approved, algorithm)
		}
	}
	return approved
}

func TestSupportedAlgorithms_SoftwareListsItsFullSet(t *testing.T) {
	svc := keyManagementService(t)
	resp, err := svc.GetSupportedAlgorithms(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)

	want := softwareAlgorithms
	if fips140.Enabled() {
		want = fipsApproved(softwareAlgorithms)
	}
	assert.ElementsMatch(t, want, resp.Algorithms)
}

func TestSupportedAlgorithms_FIPSModeOmitsUnapprovedAlgorithms(t *testing.T) {
	declared := types.KeyAlgorithms{
		Ed25519:   true,
		X25519:    true,
		Symmetric: []types.SymmetricAlgorithm{types.SymmetricAES256GCM, types.SymmetricChaCha20Poly1305, types.SymmetricXChaCha20Poly1305},
	}

	assert.ElementsMatch(t, []transport.KeyAlgorithm{
		transport.KeyAlgorithmEd25519, transport.KeyAlgorithmAES256GCM,
	}, supportedAlgorithms(declared, true))
	assert.ElementsMatch(t, []transport.KeyAlgorithm{
		transport.KeyAlgorithmEd25519, transport.KeyAlgorithmX25519, transport.KeyAlgorithmAES256GCM,
		transport.KeyAlgorithmChaCha20Poly1305, transport.KeyAlgorithmXChaCha20Poly1305,
	}, supportedAlgorithms(declared, false))
}

func TestSupportedAlgorithms_OmitsWhatIsNotDeclaredOrNamed(t *testing.T) {
	// Capability flags without a declaration advertise nothing.
	assert.Empty(t, supportedAlgorithms(types.KeyAlgorithms{}, false))

	// A declared shape the transport vocabulary has no name for is omitted.
	declared := types.KeyAlgorithms{
		RSAKeySizes: []int{1024},
		ECDSACurves: []string{"P-224"},
		Symmetric:   []types.SymmetricAlgorithm{types.SymmetricAlgorithm("aes-512-gcm")},
		MLDSA:       []types.QuantumAlgorithm{types.QuantumAlgorithmMLDSA65},
	}
	assert.Empty(t, supportedAlgorithms(declared, false))
}

func TestBuildAlgorithmsResponse_AgreesWithGetSupportedAlgorithms(t *testing.T) {
	svc := keyManagementService(t)
	supported, err := svc.GetSupportedAlgorithms(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)

	resp := BuildAlgorithmsResponse([]BackendType{BackendSoftware}, func(name string) (types.Capabilities, error) {
		b, _, err := svc.resolveTenantBackendWithName(name, "")
		if err != nil {
			return types.Capabilities{}, err
		}
		return b.KeyProvider().Capabilities(), nil
	})

	// Every signing key the Algorithms RPC reports is one GetSupportedAlgorithms
	// reports, and the reverse.
	signing := map[transport.KeyAlgorithm]bool{
		transport.KeyAlgorithmEd25519: true,
	}
	for _, algorithm := range rsaKeyAlgorithms {
		signing[algorithm] = true
	}
	for _, algorithm := range ecdsaKeyAlgorithms {
		signing[algorithm] = true
	}
	var want []transport.KeyAlgorithm
	for _, algorithm := range supported.Algorithms {
		if signing[algorithm] {
			want = append(want, algorithm)
		}
	}

	var got []transport.KeyAlgorithm
	for _, info := range resp.Signing {
		for _, size := range info.KeySizes {
			got = append(got, rsaKeyAlgorithms[size])
		}
		for _, curve := range info.Curves {
			got = append(got, ecdsaKeyAlgorithms[curve])
		}
		if info.Algorithm == types.AlgorithmEd25519.String() {
			got = append(got, transport.KeyAlgorithmEd25519)
		}
	}
	require.NotEmpty(t, want)
	assert.ElementsMatch(t, want, got)
	assert.Empty(t, resp.KeyEncapsulation, "the software backend declares no ML-KEM keys")
}

func TestBuildAlgorithmsResponse_UnknownBackendContributesNothing(t *testing.T) {
	svc := keyManagementService(t)
	resp := BuildAlgorithmsResponse([]BackendType{"nope"}, func(name string) (types.Capabilities, error) {
		b, _, err := svc.resolveTenantBackendWithName(name, "")
		if err != nil {
			return types.Capabilities{}, err
		}
		return b.KeyProvider().Capabilities(), nil
	})
	assert.Empty(t, resp.Signing)
	assert.Empty(t, resp.KeyEncapsulation)
}
