// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package attestation_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// newFileStore opens an empty file-backed trust store that is closed when the
// test ends.
func newFileStore(t *testing.T) *truststore.FileStore {
	t.Helper()

	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{BaseDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, store.Close())
	})
	return store
}

// failingQueryStore is a trust store whose purpose query always fails.
type failingQueryStore struct {
	*truststore.FileStore
	err error
}

func (s *failingQueryStore) CertificatesByPurpose(truststore.CertPurpose) ([]*x509.Certificate, error) {
	return nil, s.err
}

func TestLoadTrust_CarriesTheApplicationPolicy(t *testing.T) {
	apps := attesttest.Applications()
	revocation := attesttest.NoRevocations()

	trust, err := attestation.LoadTrust(newFileStore(t), apps, revocation)

	require.NoError(t, err)
	assert.NotNil(t, trust.Roots)
	assert.Equal(t, apps, trust.Applications)
	assert.Same(t, revocation, trust.Revocation)
}

func TestLoadTrust_NoRevocationSourceRefuses(t *testing.T) {
	trust, err := attestation.LoadTrust(newFileStore(t), attesttest.Applications(), nil)

	require.Error(t, err)
	assert.Nil(t, trust)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.ErrorIs(t, err, xkms.ErrNoAndroidRevocationSource)
}

func TestLoadTrust_NilStoreRefuses(t *testing.T) {
	trust, err := attestation.LoadTrust(nil, attesttest.Applications(), attesttest.NoRevocations())

	require.Error(t, err)
	assert.Nil(t, trust)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.ErrorIs(t, err, xkms.ErrAttestationNilTrustStore)
}

func TestLoadTrust_StoreQueryFailureRefuses(t *testing.T) {
	queryErr := errors.New("trust store unreadable")
	store := &failingQueryStore{FileStore: newFileStore(t), err: queryErr}

	trust, err := attestation.LoadTrust(store, attesttest.Applications(), attesttest.NoRevocations())

	require.Error(t, err)
	assert.Nil(t, trust)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.ErrorIs(t, err, xkms.ErrAttestationTrustStoreQuery)
	assert.ErrorIs(t, err, queryErr)
}

func TestLoadTrust_UnconfiguredApplicationsRefuses(t *testing.T) {
	trust, err := attestation.LoadTrust(newFileStore(t), pairing.ApplicationPolicy{}, attesttest.NoRevocations())

	require.Error(t, err)
	assert.Nil(t, trust)
	assert.ErrorIs(t, err, attestation.ErrDeviceAttestVerifyFailed)
	assert.ErrorIs(t, err, pairing.ErrApplicationPolicyUnconfigured)
}

// TestLoadTrust_ExcludesSyncedForgedGoogleRoot pins that only anchors stored
// for the Android hardware purpose reach the pool. A root synced from an
// external store under the synced purpose, even one claiming Google's name,
// must not be able to vouch for a phone.
func TestLoadTrust_ExcludesSyncedForgedGoogleRoot(t *testing.T) {
	tests := []struct {
		name    string
		purpose truststore.CertPurpose
		trusted bool
	}{
		{name: "android hardware purpose is trusted", purpose: truststore.PurposeAndroidHardware, trusted: true},
		{name: "synced purpose is excluded", purpose: truststore.PurposeSynced, trusted: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forged := attesttest.NewCA(t, "Google Hardware Attestation Root")
			store := newFileStore(t)
			require.NoError(t, store.AddCertificateWithOptions(forged.Cert,
				&truststore.AddCertificateOptions{Purpose: tt.purpose}))

			trust, err := attestation.LoadTrust(store, attesttest.Applications(), attesttest.NoRevocations())
			require.NoError(t, err)

			_, err = forged.Cert.Verify(x509.VerifyOptions{
				Roots:     trust.Roots,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if tt.trusted {
				assert.NoError(t, err)
				return
			}
			var unknownAuthority x509.UnknownAuthorityError
			assert.ErrorAs(t, err, &unknownAuthority)
		})
	}
}
