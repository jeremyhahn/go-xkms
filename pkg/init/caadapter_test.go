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

package initialize

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCAAdapter_CABundle_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:      newMockCA(t),
		caBundleErr: errors.New("bundle unavailable"),
	}
	adapter := NewCAAdapter(errCA, "")

	_, err := adapter.CABundle()
	assert.Error(t, err)
}
func TestCAAdapter_CACertificate_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:    newMockCA(t),
		caCertErr: errors.New("cert unavailable"),
	}
	adapter := NewCAAdapter(errCA, "")

	_, err := adapter.CACertificate(t.Context())
	assert.Error(t, err)
}
func TestCAAdapter_CACertificate_ReturnsCACertificate(t *testing.T) {
	base := newMockCA(t)
	adapter := NewCAAdapter(base, "")

	got, err := adapter.CACertificate(t.Context())
	require.NoError(t, err)
	want, err := base.CACertificate()
	require.NoError(t, err)
	assert.True(t, got.Equal(want))
}
func TestCAAdapter_CACertificate_CanceledContext(t *testing.T) {
	adapter := NewCAAdapter(newMockCA(t), "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := adapter.CACertificate(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}
func TestCAAdapter_IssueCertificate_EmptySANsNotMapped(t *testing.T) {
	base := newMockCA(t)
	sanCA := &mockCAWithSANs{mockCA: base}
	adapter := NewCAAdapter(sanCA, "")

	req := &qrdbsdk.IssueCertRequest{
		PublicKey:  newTestPublicKey(t),
		CommonName: "no-sans",
	}

	_, err := adapter.IssueCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.Nil(t, sanCA.lastSANs)
}
func TestCAAdapter_IssueCertificate_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:       newMockCA(t),
		issueCertErr: errors.New("issuance failed"),
	}
	adapter := NewCAAdapter(errCA, "")

	req := &qrdbsdk.IssueCertRequest{
		PublicKey:    newTestPublicKey(t),
		CommonName:   "fail-cn",
		ValidityDays: 365,
	}

	_, err := adapter.IssueCertificate(context.Background(), req)
	assert.Error(t, err)
}
func TestCAAdapter_IssueCertificate_SANsPassedThrough(t *testing.T) {
	base := newMockCA(t)
	sanCA := &mockCAWithSANs{mockCA: base}
	adapter := NewCAAdapter(sanCA, "")

	req := &qrdbsdk.IssueCertRequest{
		PublicKey:  newTestPublicKey(t),
		CommonName: "with-sans",
		SANs:       []string{"foo.example.com", "bar.example.com"},
	}

	_, err := adapter.IssueCertificate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, sanCA.lastSANs)
	assert.Equal(t, []string{"foo.example.com", "bar.example.com"}, sanCA.lastSANs.DNS)
}

// TestCAAdapter_IssueCertificate_SPIFFEStampFailurePropagates verifies that
// IssueCertificate surfaces a SPIFFE URI construction failure (an empty
// CommonName leaves the workload name empty) rather than issuing a
// certificate with a malformed or missing SPIFFE SAN.
func TestCAAdapter_IssueCertificate_SPIFFEStampFailurePropagates(t *testing.T) {
	mCA := newMockCA(t)
	adapter := NewCAAdapter(mCA, "xkms.example.com")

	req := &qrdbsdk.IssueCertRequest{
		PublicKey:    newTestPublicKey(t),
		CommonName:   "",
		ValidityDays: 365,
	}

	issued, err := adapter.IssueCertificate(context.Background(), req)
	assert.ErrorIs(t, err, spiffe.ErrNameEmpty)
	assert.Nil(t, issued)
}
func TestCAAdapter_IssueCertificate_WithoutSANs(t *testing.T) {
	mCA := newMockCA(t)
	adapter := NewCAAdapter(mCA, "")

	req := &qrdbsdk.IssueCertRequest{
		PublicKey:    newTestPublicKey(t),
		CommonName:   "no-sans",
		ValidityDays: 365,
	}

	issued, err := adapter.IssueCertificate(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, issued)
	assert.NotNil(t, issued.Certificate)
}
func TestCAAdapter_IssueCertificate_WithSANs(t *testing.T) {
	mCA := newMockCA(t)
	adapter := NewCAAdapter(mCA, "")

	publicKey := newTestPublicKey(t)
	req := &qrdbsdk.IssueCertRequest{
		PublicKey:    publicKey,
		CommonName:   "test-cn",
		SANs:         []string{"dns1.example.com", "dns2.example.com"},
		ValidityDays: 365,
	}

	issued, err := adapter.IssueCertificate(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.NotNil(t, issued.Certificate)
	assert.NotEmpty(t, issued.CertPEM)
	assert.True(t, publicKey.Equal(issued.Certificate.PublicKey), "the certificate must bind the requester's key")
}

// TestCAAdapter_IssueCertificate_RequiresPublicKey verifies that a request
// naming no key is refused rather than certifying a key the CA invents.
func TestCAAdapter_IssueCertificate_RequiresPublicKey(t *testing.T) {
	adapter := NewCAAdapter(newMockCA(t), "")

	issued, err := adapter.IssueCertificate(context.Background(), &qrdbsdk.IssueCertRequest{CommonName: "keyless"})
	assert.ErrorIs(t, err, ca.ErrPublicKeyRequired)
	assert.Nil(t, issued)
}

// newTestPublicKey returns the public half of a fresh P-256 key, standing in
// for the key a certificate requester keeps.
func newTestPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &key.PublicKey
}
func TestCAAdapter_SignCSR_Error(t *testing.T) {
	errCA := &errorCA{
		mockCA:     newMockCA(t),
		signCSRErr: errors.New("sign failed"),
	}
	adapter := NewCAAdapter(errCA, "")

	csrPEM, _ := generateTestCSR(t, "test-cn")
	_, err := adapter.SignCSR(context.Background(), csrPEM, &qrdbsdk.SignCSROptions{
		ValidityDays: 365,
	})
	assert.Error(t, err)
}

// TestCAAdapter_SignCSR_StampsSPIFFEWhenTrustDomainConfigured verifies that a
// non-empty spiffeTrustDomain makes SignCSR stamp the system-tenant SPIFFE
// SAN fields onto the underlying SignOptions, not just pass validity/profile
// through unchanged.
// TestCAAdapter_SignCSR_IssuesTheHolderSubject: a holder certificate carries
// exactly go-qrdb's RawSubject (CN=<holder>, OU=<tenant>, OU=<profile>) and
// no SPIFFE SAN, even with a trust domain configured: go-qrdb refuses a
// holder certificate with any subject alternative name.
func TestCAAdapter_SignCSR_IssuesTheHolderSubject(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "xkms.example.com")

	csrPEM, _ := generateTestCSR(t, "requested-cn")
	opts := &qrdbsdk.SignCSROptions{TenantID: "acme", Username: "officer-1", Profile: "security-officer", ValidityDays: 365}
	_, err := adapter.SignCSR(context.Background(), csrPEM, opts)
	require.NoError(t, err)
	require.NotNil(t, rec.lastSignOpts)
	want, err := opts.RawSubject()
	require.NoError(t, err)
	assert.Equal(t, want, rec.lastSignOpts.RawSubject)
	assert.Empty(t, rec.lastSignOpts.SPIFFETrustDomain)
	assert.Equal(t, "acme", rec.lastSignOpts.TenantID, "the tenant the CA stamps as the first OU")
	assert.Nil(t, rec.lastSignOpts.SANS)
	assert.Empty(t, rec.lastSignOpts.Profile, "go-qrdb's holder label is an OU, not a CA profile")
}

// TestCAAdapter_SignCSR_RefusesAnUnnamedHolder: without a registered holder
// and tenant there is nothing to name, and nothing is signed.
func TestCAAdapter_SignCSR_RefusesAnUnnamedHolder(t *testing.T) {
	rec := newRecordingCA(t)
	adapter := NewCAAdapter(rec, "")
	csrPEM, _ := generateTestCSR(t, "requested-cn")

	_, err := adapter.SignCSR(context.Background(), csrPEM, nil)
	require.ErrorIs(t, err, ErrNilSignOptions)
	_, err = adapter.SignCSR(context.Background(), csrPEM, &qrdbsdk.SignCSROptions{Username: "officer-1"})
	require.Error(t, err, "no tenant")
	assert.Nil(t, rec.lastSignOpts, "nothing reached the CA")
}
