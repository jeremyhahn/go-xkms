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

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	tpmbackend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// newSimulatorCABackend returns an xkms.Backend whose keys live inside an
// in-process go-tpm-tools simulator.
//
// The simulator is auto-provisioned (EK + SRK) by NewBackend and all state
// lives under t.TempDir(), so the test needs no external swtpm process and
// never touches the host's /dev/tpmrm0.
func newSimulatorCABackend(t *testing.T) (xkms.Backend, func()) {
	t.Helper()

	tpmBackend, err := tpmbackend.NewBackend(&tpmbackend.Config{
		UseSimulator: true,
		KeyDir:       t.TempDir(),
		CN:           "ca-multi-keystore-test",
	})
	require.NoError(t, err, "TPM simulator backend must construct and auto-provision")

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     tpmBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	cleanup := func() {
		require.NoError(t, tpmBackend.Close())
	}
	return backend, cleanup
}

// tpm2KeyExists reports whether a key with the given attributes is resolvable as
// a signer inside the TPM-backed backend — i.e. the key material physically
// lives in the TPM.
func tpm2KeyExists(t *testing.T, backend xkms.Backend, attrs *types.KeyAttributes) bool {
	t.Helper()
	signer, err := backend.Signer(context.Background(), attrs)
	return err == nil && signer != nil
}

// TestCA_TPM2Key_InitAndSign proves per-key routing to the TPM: the CA primary
// (Keys[0]) is a software ECDSA key, and Keys[1] is an ECDSA key routed to the
// tpm2 backend. After Init the TPM2 key must physically exist in the swtpm, and
// the CA (signing with its software primary) must issue a verifiable cert.
func TestCA_TPM2Key_InitAndSign(t *testing.T) {
	tpmBackend, cleanup := newSimulatorCABackend(t)
	defer cleanup()

	swBackend := newInMemoryBackend(t)

	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		switch st {
		case types.StoreTPM2:
			return tpmBackend, nil
		default:
			return swBackend, nil
		}
	}

	const cn = "TPM2 Secondary Root CA"
	id := Identity{
		Subject:      Subject{CommonName: cn, Organization: "Test Org"},
		Valid:        DefaultRootValidityYears,
		KeystoreType: types.StoreSoftware,
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmECDSA, types.StoreSoftware), // [0] primary (software)
			keyConfig(types.AlgorithmECDSA, types.StoreTPM2),     // [1] TPM-backed
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

	// The secondary TPM2 ECDSA key physically exists inside the swtpm.
	tpmAttrs, err := types.KeyAttributesFromConfig(keyConfig(types.AlgorithmECDSA, types.StoreTPM2))
	require.NoError(t, err)
	tpmAttrs.CN = cn
	tpmAttrs.KeyType = types.KeyTypeCA
	require.True(t, tpm2KeyExists(t, tpmBackend, tpmAttrs),
		"Keys[1] (store=tpm2) must land in the TPM after Init")

	// The CA can issue and verify a certificate (signed by the software primary).
	issued, err := root.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "leaf.tpm-secondary.example.com"},
		Valid:   1,
	})
	require.NoError(t, err)
	_, err = root.Verify(issued.Certificate)
	require.NoError(t, err)
}

// TestCA_TPM2PrimaryKey_InitAndSign proves the strongest claim: when Keys[0]
// (the primary signing key) is store=tpm2, the self-signed CA certificate is
// produced by a key that physically lives in the swtpm, and that TPM key signs
// every issued certificate.
func TestCA_TPM2PrimaryKey_InitAndSign(t *testing.T) {
	tpmBackend, cleanup := newSimulatorCABackend(t)
	defer cleanup()

	swBackend := newInMemoryBackend(t)

	factory := func(cn string, st types.StoreType) (xkms.Backend, error) {
		switch st {
		case types.StoreTPM2:
			return tpmBackend, nil
		default:
			return swBackend, nil
		}
	}

	const cn = "TPM2 Primary Root CA"
	id := Identity{
		Subject:      Subject{CommonName: cn, Organization: "Test Org"},
		Valid:        DefaultRootValidityYears,
		KeystoreType: types.StoreTPM2,
		Keys: []*types.KeyConfig{
			keyConfig(types.AlgorithmECDSA, types.StoreTPM2), // [0] primary (TPM-backed)
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

	// The primary CA key physically lives in the swtpm.
	tpmAttrs, err := types.KeyAttributesFromConfig(keyConfig(types.AlgorithmECDSA, types.StoreTPM2))
	require.NoError(t, err)
	tpmAttrs.CN = cn
	tpmAttrs.KeyType = types.KeyTypeCA
	require.True(t, tpm2KeyExists(t, tpmBackend, tpmAttrs),
		"primary CA key (store=tpm2) must live in the TPM")

	// The CA's public key matches the TPM signer's public key.
	caCert, err := root.CACertificate()
	require.NoError(t, err)
	tpmSigner, err := tpmBackend.Signer(context.Background(), tpmAttrs)
	require.NoError(t, err)
	require.Equal(t,
		mustMarshalPub(t, tpmSigner.Public()),
		mustMarshalPub(t, caCert.PublicKey),
		"CA certificate must bind the TPM-resident public key")

	// Issuance signs with the TPM key and verifies against the CA root.
	issued, err := root.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "leaf.tpm-primary.example.com"},
		Valid:   1,
	})
	require.NoError(t, err)
	_, err = root.Verify(issued.Certificate)
	require.NoError(t, err)
}

func mustMarshalPub(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return der
}
