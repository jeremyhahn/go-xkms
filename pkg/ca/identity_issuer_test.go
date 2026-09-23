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

package ca

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// clusterTestConfig returns a three-identity hierarchy with SIBLING
// intermediates: root, a platform CA (issuing, SelectedCA=1), and a cluster
// CA — both direct children of the root via ParentCA.
func clusterTestConfig() *MultiIdentityCAConfig {
	cfg := DefaultMultiIdentityCAConfigWithIntermediate()
	cfg.Identity[0].Subject.CommonName = "Test Root CA"
	cfg.Identity[0].Keys[0].KeyType = "CA"
	cfg.Identity[1].Subject.CommonName = "Test Platform CA"
	cfg.Identity[1].Keys[0].KeyType = "CA"
	cfg.Identity[1].ParentCA = "Test Root CA"
	clusterKeys := DefaultKeyConfig()
	clusterKeys[0].KeyType = "CA"
	cfg.Identity = append(cfg.Identity, Identity{
		Subject: Subject{
			CommonName:   "Test Cluster CA",
			Organization: "Organization",
			Country:      "US",
		},
		Valid:             DefaultIntermediateValidityYears,
		Keys:              clusterKeys,
		ParentCA:          "Test Root CA",
		MaxPathLengthZero: true,
	})
	return cfg
}

// newClusterTestCA constructs and initializes a CA over in-memory stores from
// the given config, returning the CA plus its stores so tests can construct a
// second instance over the same state (Load paths).
func newClusterTestCA(t *testing.T, cfg *MultiIdentityCAConfig) (*CA, xkms.Backend, certstore.CertStore) {
	t.Helper()

	swBackend, err := software.NewBackend(&software.Config{
		KeyStorage: storage.NewMemory(),
	})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{
		Backend:     swBackend,
		CertStorage: storage.NewMemory(),
	})
	require.NoError(t, err)

	cs, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(storage.NewMemory()),
	})
	require.NoError(t, err)

	testCA := &CA{
		config:      cfg,
		keyStore:    backend,
		keystoreMap: map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:   cs,
		revocations: make(map[string]*RevocationInfo),
		serialGen:   NewSerialGenerator(NewMemoryStorage()),
		profiles:    NewDefaultProfileRegistry(),
	}
	require.NoError(t, testCA.Init(context.Background()))
	return testCA, backend, cs
}

// ---------------------------------------------------------------------------
// ParentCA sibling topology
// ---------------------------------------------------------------------------

func TestCreateIntermediates_SiblingTopology(t *testing.T) {
	testCA, _, cs := newClusterTestCA(t, clusterTestConfig())

	platformCert, err := cs.GetCertificate("Test Platform CA")
	require.NoError(t, err)
	clusterCert, err := cs.GetCertificate("Test Cluster CA")
	require.NoError(t, err)

	// Both intermediates are direct children of the ROOT (siblings), not a
	// sequential chain.
	require.NoError(t, platformCert.CheckSignatureFrom(testCA.rootCert))
	require.NoError(t, clusterCert.CheckSignatureFrom(testCA.rootCert))
	assert.Error(t, clusterCert.CheckSignatureFrom(platformCert))
}

func TestCreateIntermediates_SequentialDefaultPreserved(t *testing.T) {
	cfg := clusterTestConfig()
	// Clearing ParentCA restores the historical behavior: each intermediate
	// is signed by the previous identity in the list.
	cfg.Identity[2].ParentCA = ""

	testCA, _, cs := newClusterTestCA(t, cfg)

	platformCert, err := cs.GetCertificate("Test Platform CA")
	require.NoError(t, err)
	clusterCert, err := cs.GetCertificate("Test Cluster CA")
	require.NoError(t, err)

	require.NoError(t, clusterCert.CheckSignatureFrom(platformCert))
	assert.Error(t, clusterCert.CheckSignatureFrom(testCA.rootCert))
}

func TestValidate_ParentCAReferences(t *testing.T) {
	// Root must not reference a parent.
	cfg := clusterTestConfig()
	cfg.Identity[0].ParentCA = "Somebody"
	require.Error(t, cfg.Validate())

	// Unknown parent reference is rejected with the typed error.
	cfg = clusterTestConfig()
	cfg.Identity[2].ParentCA = "No Such CA"
	err := cfg.Validate()
	require.Error(t, err)
	var unknownErr *ErrUnknownParentCA
	require.ErrorAs(t, err, &unknownErr)
	assert.Equal(t, "Test Cluster CA", unknownErr.Identity)
	assert.Equal(t, "No Such CA", unknownErr.ParentCA)

	// Forward references are rejected: identity[1] cannot be signed by
	// identity[2], which does not exist yet at creation time.
	cfg = clusterTestConfig()
	cfg.Identity[1].ParentCA = "Test Cluster CA"
	err = cfg.Validate()
	require.Error(t, err)
	require.ErrorAs(t, err, &unknownErr)

	// The valid sibling topology passes.
	require.NoError(t, clusterTestConfig().Validate())
}

// ---------------------------------------------------------------------------
// IssuerForIdentity
// ---------------------------------------------------------------------------

func TestIssuerForIdentity_ClusterIntermediate(t *testing.T) {
	testCA, _, cs := newClusterTestCA(t, clusterTestConfig())

	signer, cert, err := testCA.IssuerForIdentity(context.Background(), "Test Cluster CA")
	require.NoError(t, err)
	require.NotNil(t, signer)
	require.NotNil(t, cert)

	assert.Equal(t, "Test Cluster CA", cert.Subject.CommonName)
	assert.True(t, cert.IsCA)

	// The returned signer's public key matches the certificate.
	certFromStore, err := cs.GetCertificate("Test Cluster CA")
	require.NoError(t, err)
	assert.Equal(t, certFromStore.PublicKey, signer.Public())

	// The interface assertion consumers rely on holds.
	var _ IdentityIssuer = testCA
}

func TestIssuerForIdentity_Errors(t *testing.T) {
	testCA, _, _ := newClusterTestCA(t, clusterTestConfig())

	// Unknown identity.
	_, _, err := testCA.IssuerForIdentity(context.Background(), "No Such CA")
	require.Error(t, err)
	var notFound *ErrIdentityNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "No Such CA", notFound.CommonName)

	// Uninitialized CA.
	uninitialized := &CA{config: clusterTestConfig()}
	_, _, err = uninitialized.IssuerForIdentity(context.Background(), "Test Cluster CA")
	require.ErrorIs(t, err, ErrNotInitialized)
}

// ---------------------------------------------------------------------------
// Load verifies all intermediates
// ---------------------------------------------------------------------------

func TestLoad_AllIntermediates(t *testing.T) {
	cfg := clusterTestConfig()
	_, backend, cs := newClusterTestCA(t, cfg)

	// A second CA instance over the same stores loads successfully and can
	// issue from the non-selected cluster intermediate afterwards.
	reloaded := &CA{
		config:          cfg,
		keyStore:        backend,
		keystoreMap:     map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:       cs,
		revocationStore: storage.NewMemory(),
		revocations:     make(map[string]*RevocationInfo),
		serialGen:       NewSerialGenerator(NewMemoryStorage()),
		profiles:        NewDefaultProfileRegistry(),
	}
	require.NoError(t, reloaded.Load(context.Background()))

	signer, cert, err := reloaded.IssuerForIdentity(context.Background(), "Test Cluster CA")
	require.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, "Test Cluster CA", cert.Subject.CommonName)
}

func TestLoad_MissingNonSelectedIntermediateFails(t *testing.T) {
	cfg := clusterTestConfig()
	testCA, backend, _ := newClusterTestCA(t, cfg)

	// Rebuild a cert store containing only root + the SELECTED intermediate;
	// the cluster intermediate is missing, so Load must fail closed instead
	// of leaving a non-selected identity silently unusable.
	partial, err := certstore.New(&certstore.Config{
		CertStorage: storage.NewCertAdapter(storage.NewMemory()),
	})
	require.NoError(t, err)
	rootCert, err := testCA.certStore.GetCertificate("Test Root CA")
	require.NoError(t, err)
	platformCert, err := testCA.certStore.GetCertificate("Test Platform CA")
	require.NoError(t, err)
	require.NoError(t, partial.StoreCertificate(rootCert))
	require.NoError(t, partial.StoreCertificate(platformCert))

	reloaded := &CA{
		config:          cfg,
		keyStore:        backend,
		keystoreMap:     map[types.StoreType]xkms.Backend{types.StoreSoftware: backend},
		certStore:       partial,
		revocationStore: storage.NewMemory(),
		revocations:     make(map[string]*RevocationInfo),
		serialGen:       NewSerialGenerator(NewMemoryStorage()),
		profiles:        NewDefaultProfileRegistry(),
	}
	err = reloaded.Load(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCertificateNotFound))
	assert.Contains(t, err.Error(), "Test Cluster CA")
}
