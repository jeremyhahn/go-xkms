//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errCertStoreUnavailable = errors.New("cert store unavailable")

// failingCertStore is a certificate store whose lookups fail with an error
// other than "not found".
type failingCertStore struct {
	*mockCertStoreCov
}

func (failingCertStore) Get(*types.KeyAttributes) (*x509.Certificate, error) {
	return nil, errCertStoreUnavailable
}

// withEKCertSources points the harness at the given EK cert handle and
// certificate store, restoring both when the test ends.
func withEKCertSources(t *testing.T, h *simHarness, certHandle uint32, certStore store.CertificateStorer) {
	t.Helper()
	savedHandle, savedStore := h.TPM.config.EK.CertHandle, h.TPM.certStore
	h.TPM.config.EK.CertHandle = certHandle
	h.TPM.certStore = certStore
	t.Cleanup(func() {
		h.TPM.config.EK.CertHandle = savedHandle
		h.TPM.certStore = savedStore
	})
}

// TestEKCertificate_CertStoreOnly proves that with no NV cert handle the
// certificate store is the only source: no store means no certificate, and
// a store failure other than "not found" is surfaced as is.
func TestEKCertificate_CertStoreOnly(t *testing.T) {
	h := newSimHarness(t, nil)

	t.Run("no certificate store", func(t *testing.T) {
		withEKCertSources(t, h, 0, nil)
		cert, err := h.TPM.EKCertificate()
		assert.ErrorIs(t, err, ErrEndorsementCertNotFound)
		assert.Nil(t, cert)
	})

	t.Run("certificate store fails", func(t *testing.T) {
		withEKCertSources(t, h, 0, failingCertStore{&mockCertStoreCov{}})
		cert, err := h.TPM.EKCertificate()
		assert.ErrorIs(t, err, errCertStoreUnavailable)
		assert.Nil(t, cert)
	})
}

// TestEKCertificate_FallsBackToCertStore proves an EK certificate missing
// from every NV index is served from the certificate store.
func TestEKCertificate_FallsBackToCertStore(t *testing.T) {
	h := newSimHarness(t, nil)
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	stored := &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: ekAttrs.CN}}
	withEKCertSources(t, h, 0x01C0FFF0, &mockCertStoreCov{
		certs: map[string]*x509.Certificate{ekAttrs.CN: stored},
	})

	cert, err := h.TPM.EKCertificate()
	require.NoError(t, err)
	assert.Equal(t, stored.SerialNumber, cert.SerialNumber)
}

// TestEKCertificate_RefusesBadEKConfig proves an EK configuration that
// cannot describe a key is refused before any certificate lookup.
func TestEKCertificate_RefusesBadEKConfig(t *testing.T) {
	h := newSimHarness(t, nil)
	saved := *h.TPM.config.EK
	t.Cleanup(func() { *h.TPM.config.EK = saved })
	h.TPM.config.EK.KeyAlgorithm = x509.ECDSA.String()
	h.TPM.config.EK.RSAConfig = nil
	h.TPM.config.EK.ECCConfig = &store.ECCConfig{Curve: "no-such-curve"}

	cert, err := h.TPM.EKCertificate()
	assert.Error(t, err)
	assert.Nil(t, cert)
}

// TestEKCertificate_ReleasesPasswords proves EKCertificate leaves no
// password enclave locked, whether the certificate is found or not. It used
// to leak the EK password and hierarchy auth it built on every call.
func TestEKCertificate_ReleasesPasswords(t *testing.T) {
	h := newSimHarness(t, nil)
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	stored := &x509.Certificate{SerialNumber: big.NewInt(7)}

	tests := []struct {
		name      string
		certStore store.CertificateStorer
	}{
		{"found", &mockCertStoreCov{certs: map[string]*x509.Certificate{ekAttrs.CN: stored}}},
		{"not found", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withEKCertSources(t, h, 0, tt.certStore)
			before := lockedBytesInUse(t)
			for i := 0; i < 3; i++ {
				_, err := h.TPM.EKCertificate()
				if tt.certStore == nil {
					require.ErrorIs(t, err, ErrEndorsementCertNotFound)
				} else {
					require.NoError(t, err)
				}
			}
			assert.Equal(t, before, lockedBytesInUse(t), "EKCertificate must not leave a password enclave locked")
		})
	}
}
