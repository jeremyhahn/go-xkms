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

//go:build pkcs11

package ca

import (
	"context"
	"os"
	"testing"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

const (
	softHSMTokenLabel = "quicbaas-dev"
	softHSMPIN        = "1234"
)

// softHSMLibraryPath returns the first SoftHSM library path that exists, or ""
// when SoftHSM is not installed.
func softHSMLibraryPath() string {
	for _, p := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// newSoftHSMCABackend constructs a PKCS#11 xkms.Backend against the SoftHSM
// "quicbaas-dev" token. Constructing the backend proves it compiles and wires;
// the caller probes a real operation to decide whether the token is usable.
func newSoftHSMCABackend(t *testing.T) xkms.Backend {
	t.Helper()

	lib := softHSMLibraryPath()
	if lib == "" {
		t.Skip("SoftHSM library not found")
	}

	// Backend construction must always succeed (no token I/O yet) — this is the
	// "the pkcs11 backend constructs" guarantee.
	p11, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		CN:          "ca-multi-keystore-pkcs11",
		Library:     lib,
		TokenLabel:  softHSMTokenLabel,
		PIN:         softHSMPIN,
		KeyStorage:  storage.NewMemory(),
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err, "pkcs11 backend must construct")

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     p11,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	return backend
}

// TestCA_PKCS11Key_InitAndSign routes a secondary CA key to a SoftHSM PKCS#11
// backend. The backend construction is always exercised; the live init/sign
// portion skips when the "quicbaas-dev" token is unavailable so the build stays
// green on machines without a provisioned HSM token.
func TestCA_PKCS11Key_InitAndSign(t *testing.T) {
	p11Backend := newSoftHSMCABackend(t)

	// Probe the token with a real key generation. If it fails the token is not
	// provisioned in this environment; skip the live portion.
	probeAttrs, err := types.KeyAttributesFromConfig(keyConfig(types.AlgorithmECDSA, types.StorePKCS11))
	require.NoError(t, err)
	probeAttrs.CN = "pkcs11-probe"
	if _, err := p11Backend.GenerateECDSA(context.Background(), probeAttrs); err != nil {
		t.Skipf("SoftHSM token %q not usable (construct OK, live op skipped): %v", softHSMTokenLabel, err)
	}
	defer func() { _ = p11Backend.DeleteKey(context.Background(), probeAttrs) }()

	swBackend := newInMemoryBackend(t)
	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		if st == types.StorePKCS11 {
			return p11Backend, nil
		}
		return swBackend, nil
	}

	const cn = "PKCS11 Secondary Root CA"
	id := Identity{
		Subject:      Subject{CommonName: cn, Organization: "Test Org"},
		Valid:        DefaultRootValidityYears,
		KeystoreType: types.StoreSoftware,
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmECDSA, types.StoreSoftware), // [0] primary (software)
			keyConfig(types.AlgorithmECDSA, types.StorePKCS11),   // [1] HSM-backed
		},
		IsRoot:        true,
		MaxPathLength: 1,
	}

	params := &Params{
		Identity:        []Identity{id},
		KeyStore:        swBackend,
		CertStore:       newInMemoryCertStore(t),
		BackendForStore: factory,
	}

	root, _, err := NewCA(context.Background(), params)
	require.NoError(t, err)
	require.True(t, root.IsInitialized())

	// The secondary key physically lives in the HSM.
	hsmAttrs, err := types.KeyAttributesFromConfig(keyConfig(types.AlgorithmECDSA, types.StorePKCS11))
	require.NoError(t, err)
	hsmAttrs.CN = cn
	hsmAttrs.KeyType = types.KeyTypeCA
	defer func() { _ = p11Backend.DeleteKey(context.Background(), hsmAttrs) }()
	signer, err := p11Backend.Signer(context.Background(), hsmAttrs)
	require.NoError(t, err, "Keys[1] (store=pkcs11) must land in the HSM")
	require.NotNil(t, signer)

	// Issue and verify a certificate (signed by the software primary).
	issued, err := root.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "leaf.pkcs11.example.com"},
		Valid:   1,
	})
	require.NoError(t, err)
	_, err = root.Verify(issued.Certificate)
	require.NoError(t, err)
}
