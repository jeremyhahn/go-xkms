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
	"testing"

	"github.com/jeremyhahn/go-xkms/internal/softhsmtest"
	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// softHSMTokenLabel names the private token this test provisions. Nothing is
// shared with the host's SoftHSM store.
const softHSMTokenLabel = "ca-multi-keystore"

// newSoftHSMCABackend provisions a private SoftHSM2 token under t.TempDir()
// and returns a PKCS#11-backed xkms.Backend bound to it.
func newSoftHSMCABackend(t *testing.T) xkms.Backend {
	t.Helper()

	token := softhsmtest.Provision(t, softHSMTokenLabel)

	p11, err := pkcs11backend.NewBackend(&pkcs11backend.Config{
		CN:          "ca-multi-keystore-pkcs11",
		Library:     token.Library,
		TokenLabel:  token.Label,
		PIN:         types.NewLiteralSecretValue([]byte(token.UserPIN)),
		SOPIN:       types.NewLiteralSecretValue([]byte(token.SOPIN)),
		KeyStorage:  storage.NewMemory(),
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err, "pkcs11 backend must construct")

	// The token is already initialized by softhsmtest; establish the session
	// pool so key operations can run.
	require.NoError(t, p11.Login(), "pkcs11 backend must log in to the provisioned token")

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     p11,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	return backend
}

// TestCA_PKCS11Key_InitAndSign routes a secondary CA key to a PKCS#11 backend
// bound to a private SoftHSM2 token, and proves the key physically lands in
// the HSM rather than the software keystore.
func TestCA_PKCS11Key_InitAndSign(t *testing.T) {
	p11Backend := newSoftHSMCABackend(t)

	// The provisioned token must be live: prove it with a real key generation
	// before relying on it for the CA hierarchy.
	probeAttrs, err := types.KeyAttributesFromConfig(keyConfig(types.AlgorithmECDSA, types.StorePKCS11))
	require.NoError(t, err)
	probeAttrs.CN = "pkcs11-probe"
	_, err = p11Backend.GenerateECDSA(context.Background(), probeAttrs)
	require.NoError(t, err, "provisioned SoftHSM token must accept key generation")
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
		Subject: Subject{CommonName: cn, Organization: "Test Org"},
		Valid:   DefaultRootValidityYears,
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
		RevocationStore: storage.NewMemory(),
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
