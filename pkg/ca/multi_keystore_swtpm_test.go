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

//go:build swtpm

package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	tpmbackend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// swtpmAddr is the swtpm command channel used by the CA per-key TPM2 routing
// integration tests. When unreachable the tests skip so non-swtpm runs stay
// green.
const swtpmAddr = "127.0.0.1:2321"

// swtpm persistent handles. These mirror the simulator-provisioning config so a
// full EK/SSRK/IAK hierarchy is available for hardware key creation.
const (
	swtpmEKHandle   = 0x81010001
	swtpmSSRKHandle = 0x81000001
	swtpmIAKHandle  = 0x81010002
)

// newSwtpmCABackend connects to swtpm, provisions a full TPM hierarchy
// (EK + SSRK), and returns an xkms.Backend that creates and signs with keys
// inside the TPM. It skips when swtpm is unreachable. The cleanup closes the
// TPM connection so the single-client swtpm is released for later tests.
func newSwtpmCABackend(t *testing.T) (xkms.Backend, *pkgtpm2.TPM2, func()) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", swtpmAddr, 500*time.Millisecond)
	if err != nil {
		t.Skipf("swtpm not reachable at %s: %v", swtpmAddr, err)
	}
	_ = conn.Close()

	tr, err := pkgtpm2.OpenTCPTransport(swtpmAddr, "")
	if err != nil {
		t.Skipf("swtpm OpenTCPTransport failed: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	keyBackend := tpmstore.NewFileBackend(logger, storage.NewMemory())

	config := &pkgtpm2.Config{
		Device:          "swtpm",
		Hash:            "SHA-256",
		PlatformPCR:     16,
		PlatformPCRBank: pkgtpm2.PCRBankSHA256,
		EK: &pkgtpm2.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        swtpmEKHandle,
			HierarchyAuth: tpmstore.DEFAULT_PASSWORD,
			RSAConfig:     &tpmstore.RSAConfig{KeySize: 2048},
		},
		IdentityProvisioningStrategy: string(pkgtpm2.EnrollmentStrategyIAK),
		FileIntegrity:                []string{"./"},
		IAK: &pkgtpm2.IAKConfig{
			CN:                 "ca-multi-keystore-test",
			Debug:              true,
			Hash:               crypto.SHA256.String(),
			Handle:             swtpmIAKHandle,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &tpmstore.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
		SSRK: &pkgtpm2.SRKConfig{
			Handle:        swtpmSSRKHandle,
			HierarchyAuth: tpmstore.DEFAULT_PASSWORD,
			KeyAlgorithm:  x509.RSA.String(),
			RSAConfig:     &tpmstore.RSAConfig{KeySize: 2048},
		},
	}

	tpmIface, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Logger:    logger,
		Config:    config,
		Backend:   keyBackend,
		Transport: tr,
	})
	if err != nil && err != pkgtpm2.ErrNotInitialized {
		t.Skipf("NewTPM2 against swtpm failed: %v", err)
	}
	tpm := tpmIface.(*pkgtpm2.TPM2)

	// Provision the EK/SSRK/IAK hierarchy when not already present.
	if _, sErr := tpm.SSRKAttributes(); sErr != nil {
		if pErr := tpm.Provision(nil); pErr != nil {
			_ = tpm.Close()
			t.Skipf("swtpm provisioning failed: %v", pErr)
		}
	}

	tpmBackend, err := tpmbackend.NewBackendWithTPM(&tpmbackend.ExternalTPMConfig{
		TPM:        tpm,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	require.NoError(t, err)

	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     tpmBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	cleanup := func() {
		_ = tpm.Close()
	}
	return backend, tpm, cleanup
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
	tpmBackend, _, cleanup := newSwtpmCABackend(t)
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
	tpmBackend, _, cleanup := newSwtpmCABackend(t)
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
