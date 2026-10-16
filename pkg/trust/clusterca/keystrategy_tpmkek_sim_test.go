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

package clusterca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpm2test"
)

// ekCertificateForSimulator issues a certificate over the simulator's real
// Endorsement Key public key, standing in for the manufacturer EK certificate
// a physical TPM would ship with.
func ekCertificateForSimulator(t *testing.T, tpm pkgtpm2.TrustedPlatformModule) *x509.Certificate {
	t.Helper()

	// EKRSA reads the public area straight off the persistent EK handle, which
	// the simulator's auto-provisioning populated, rather than depending on a
	// cached attribute set that only a full enrollment fills in.
	ekPub, err := tpm.EKRSA()
	require.NoError(t, err, "the simulator must expose its EK public key")

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Simulator EK"},
		Issuer:       pkix.Name{CommonName: "Simulator EK Issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, ekPub, issuerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestTPMKEKStrategy_RealTPMCredentialActivation exercises the tpm-kek seed
// delivery against a REAL TPM (the in-memory simulator): the bootstrap node
// generates the seed and its provider wraps it with TPM2_MakeCredential to the
// node's EK, and a joining node recovers the identical seed with
// TPM2_ActivateCredential — proving the strategy drives the genuine
// credential-activation primitive end to end. Runs in the devcontainer via
// `make integration-test` (the `tpm_simulator` build tag); never touches host
// TPM hardware.
func TestTPMKEKStrategy_RealTPMCredentialActivation(t *testing.T) {
	ctx := context.Background()

	backend, tpm := newProvisionedSimulatorBackend(t)

	// The simulator ships no manufacturer EK certificate, so build one locally
	// around its real EK public key. MakeCredentialWithExternalEK only reads
	// the EK public key out of the certificate, and the assertion under test is
	// credential activation — not certificate chain validation — so a locally
	// issued certificate carrying the genuine EK public key exercises exactly
	// the same code path a manufacturer certificate would.
	ekCert := ekCertificateForSimulator(t, tpm)
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)
	iakPub := tpm2.Marshal(iakAttrs.TPMAttributes.Public)

	newDeps := func(bootstrapping bool) *StrategyDeps {
		return &StrategyDeps{
			NodeLocalDataDir:      t.TempDir(),
			CAConfig:              ca.DefaultMultiIdentityCAConfigWithIntermediate(),
			ReplicatedKeyStorage:  storage.NewMemory(),
			ReplicatedCertStorage: storage.NewMemory(),
			TPMSealer:             backend,
			Credentials:           tpm,
			Bootstrapping:         bootstrapping,
		}
	}

	// Bootstrap node: generate the seed; provider wraps it to the EK via a real
	// TPM2_MakeCredential.
	first := &tpmKEKStrategy{}
	_, err = first.BootstrapBackends(ctx, newDeps(true))
	require.NoError(t, err)
	require.Len(t, first.seed, clusterSeedLen)

	es, ok := EnrollmentSecretStrategyOf(first)
	require.True(t, ok)
	material, err := es.SecretProvider().ProvisionFor(ctx, &NodeSecretRequest{
		NodeURI:       "spiffe://xkms.cluster/node/10.0.0.2:63001",
		EKCertificate: ekCert,
		IAKPublic:     iakPub,
	})
	require.NoError(t, err)
	require.NotNil(t, material)

	// Joining node: recover the seed via a real TPM2_ActivateCredential.
	joiner := &tpmKEKStrategy{}
	_, err = joiner.BootstrapBackends(ctx, newDeps(false))
	require.NoError(t, err)
	joinerES, ok := EnrollmentSecretStrategyOf(joiner)
	require.True(t, ok)
	require.NoError(t, joinerES.ConsumeEnrollmentSecret(ctx, material))

	require.True(t, bytes.Equal(first.seed, joiner.seed),
		"real TPM credential activation must recover the identical cluster seed")
}

// simulatorTPMConfig is a full EK + SSRK + IAK platform configuration bound to
// the in-process go-tpm-tools simulator. Credential activation needs the IAK,
// which the backend's own first-boot path (EK + SRK only) does not create, so
// this test provisions the complete identity hierarchy itself.
func simulatorTPMConfig(t testing.TB) *pkgtpm2.Config {
	t.Helper()
	return &pkgtpm2.Config{
		UseSimulator:                 true,
		Hash:                         crypto.SHA256.String(),
		PlatformPCRBank:              pkgtpm2.PCRBankSHA256,
		IdentityProvisioningStrategy: string(pkgtpm2.EnrollmentStrategyIAK),
		EK: &pkgtpm2.EKConfig{
			CertHandle:    0x01C00002,
			Handle:        0x81010001,
			HierarchyAuth: secrettest.Literal(t, []byte(tpmstore.DEFAULT_PASSWORD)),

			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &tpmstore.RSAConfig{KeySize: 2048},
		},
		SSRK: &pkgtpm2.SRKConfig{
			Handle:        0x81000001,
			HierarchyAuth: secrettest.Literal(t, []byte(tpmstore.DEFAULT_PASSWORD)),

			KeyAlgorithm: x509.RSA.String(),
			RSAConfig:    &tpmstore.RSAConfig{KeySize: 2048},
		},
		IAK: &pkgtpm2.IAKConfig{
			CN:                 "clusterca-tpmkek-sim",
			Hash:               crypto.SHA256.String(),
			Handle:             0x81010002,
			KeyAlgorithm:       x509.RSA.String(),
			RSAConfig:          &tpmstore.RSAConfig{KeySize: 2048},
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		},
	}
}

// newProvisionedSimulatorBackend opens the in-process TPM simulator,
// provisions the full EK/SSRK/IAK hierarchy, and returns a TPM-backed
// xkms sealer plus the TPM itself. All state lives under t.TempDir(); the
// host's /dev/tpmrm0 is never opened.
func newProvisionedSimulatorBackend(t *testing.T) (*tpm2backend.Backend, pkgtpm2.TrustedPlatformModule) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	keyBackend := tpmblobtest.New(t)
	config := simulatorTPMConfig(t)

	tpmIface, err := pkgtpm2.NewTPM2(&pkgtpm2.Params{
		Logger:  logger,
		Config:  config,
		Backend: keyBackend,
	})
	// A fresh simulator has no endorsement key yet, which NewTPM2 reports as
	// ErrNotInitialized while still returning a usable handle.
	if err != nil {
		require.ErrorIs(t, err, pkgtpm2.ErrNotInitialized)
	}
	require.NotNil(t, tpmIface)
	t.Cleanup(func() { require.NoError(t, tpmIface.Close()) })

	require.NoError(t, tpmIface.Provision(nil), "simulator must provision EK, SSRK and IAK")

	// Provision is TCG-only (EK + Shared SRK); tpm2backend.NewBackendWithTPM
	// resolves its storage parent exclusively off the Platform SRK (never the
	// Shared SRK), so it must be enrolled before the backend is constructed.
	require.NoError(t, tpm2test.EnrollPlatformSRK(tpmIface, config),
		"simulator must enroll the Platform SRK xkms's own backend uses")

	backend, err := tpm2backend.NewBackendWithTPM(&tpm2backend.ExternalTPMConfig{
		TPM:        tpmIface,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	require.NoError(t, err)

	return backend, tpmIface
}
