package image

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// The trust-roots store plugs into VerifierConfig as is, with no adapter.
var _ RootStore[truststore.CertPurpose] = (*truststore.FileStore)(nil)

// newTrustStore opens an empty file-backed trust-roots store.
func newTrustStore(t *testing.T) *truststore.FileStore {
	t.Helper()
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// addRoot adds root to store under purpose.
func addRoot(t *testing.T, store *truststore.FileStore, root *x509.Certificate, purpose truststore.CertPurpose) {
	t.Helper()
	require.NoError(t, store.AddCertificateWithOptions(root, &truststore.AddCertificateOptions{Purpose: purpose}))
}

// storeVerifier builds a verifier that anchors on store's image-signer roots.
func storeVerifier(t *testing.T, f *signerFixture, store *truststore.FileStore) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(&VerifierConfig[truststore.CertPurpose]{
		Registry: f.client,
		Roots:    store,
		Purpose:  truststore.PurposeImageSigner,
	})
	require.NoError(t, err)
	return verifier
}

func TestVerifier_TrustStore_ImageSignerRootVerifies(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	f.pushAttestation(t, f.validAttestation(t))
	store := newTrustStore(t)
	addRoot(t, store, f.pki.certificate, truststore.PurposeImageSigner)

	result, err := storeVerifier(t, f, store).VerifyImage(t.Context(), f.ref)
	require.NoError(t, err)
	assert.Equal(t, f.digest, result.Digest)
}

func TestVerifier_TrustStore_OtherPurposesDoNotAnchor(t *testing.T) {
	tests := map[string]truststore.CertPurpose{
		"general":          truststore.PurposeGeneral,
		"tpm manufacturer": truststore.PurposeTPMManufacturer,
		"synced":           truststore.PurposeSynced,
	}
	for name, purpose := range tests {
		t.Run(name, func(t *testing.T) {
			f := newSignerFixture(t, registryConfig{})
			f.pushAttestation(t, f.validAttestation(t))
			store := newTrustStore(t)
			addRoot(t, store, f.pki.certificate, purpose)

			result, err := storeVerifier(t, f, store).VerifyImage(t.Context(), f.ref)
			require.ErrorIs(t, err, ErrNoTrustedRoots)
			assert.Nil(t, result)
		})
	}
}

func TestVerifier_TrustStore_ReclassifiedRootVerifiesOnNextCall(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	f.pushAttestation(t, f.validAttestation(t))
	store := newTrustStore(t)
	addRoot(t, store, f.pki.certificate, truststore.PurposeSynced)
	verifier := storeVerifier(t, f, store)

	result, err := verifier.VerifyImage(t.Context(), f.ref)
	require.ErrorIs(t, err, ErrNoTrustedRoots, "a synced root is quarantined")
	assert.Nil(t, result)

	require.NoError(t, store.SetPurpose(truststore.Fingerprint(f.pki.certificate), truststore.PurposeImageSigner))

	result, err = verifier.VerifyImage(t.Context(), f.ref)
	require.NoError(t, err, "roots are read on every call")
	assert.Equal(t, f.digest, result.Digest)
}

func TestVerifier_TrustStore_RemovedRootNoLongerVerifies(t *testing.T) {
	f := newSignerFixture(t, registryConfig{})
	f.pushAttestation(t, f.validAttestation(t))
	store := newTrustStore(t)
	addRoot(t, store, f.pki.certificate, truststore.PurposeImageSigner)
	verifier := storeVerifier(t, f, store)

	_, err := verifier.VerifyImage(t.Context(), f.ref)
	require.NoError(t, err)

	require.NoError(t, store.RemoveCertificate(truststore.Fingerprint(f.pki.certificate)))

	result, err := verifier.VerifyImage(t.Context(), f.ref)
	require.ErrorIs(t, err, ErrNoTrustedRoots)
	assert.Nil(t, result)
}
