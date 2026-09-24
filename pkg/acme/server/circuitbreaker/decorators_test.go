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

package circuitbreaker

import (
	"context"
	"crypto"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decoratorTestBreaker returns a breaker whose transitions these tests can
// drive deterministically: MaxFailures 1 so one failure opens it,
// ResetTimeout 0 so the next call probes half-open immediately, and
// SuccessThreshold 1 so a single successful probe closes it.
func decoratorTestBreaker(name string) *CircuitBreaker {
	return New(&Config{
		Name:                name,
		MaxFailures:         1,
		ResetTimeout:        0,
		HalfOpenMaxRequests: 1,
		SuccessThreshold:    1,
	})
}

var errDependencyFailed = errors.New("dependency failed")

// --- WrapChallengeVerifier ---------------------------------------------

func TestWrapChallengeVerifier_ClosedDelegatesAndRecordsOutcome(t *testing.T) {
	cb := decoratorTestBreaker("verifier-closed")
	var called bool
	inner := common.ChallengeVerifierFunc(func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		called = true
		return nil
	})

	wrapped := WrapChallengeVerifier(cb, inner)
	err := wrapped(nil, nil, "example.com", "80", "token", "keyauth")

	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, StateClosed, cb.State())
}

func TestWrapChallengeVerifier_OpenSkipsInnerAndFailsFast(t *testing.T) {
	cb := New(&Config{Name: "verifier-open", MaxFailures: 1, ResetTimeout: time.Hour})
	cb.Trip()

	var called bool
	inner := common.ChallengeVerifierFunc(func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		called = true
		return nil
	})

	wrapped := WrapChallengeVerifier(cb, inner)
	err := wrapped(nil, nil, "example.com", "80", "token", "keyauth")

	require.ErrorIs(t, err, ErrCircuitOpen)
	assert.False(t, called, "the inner verifier must not run while the breaker is open")
}

func TestWrapChallengeVerifier_HalfOpenProbeClosesOnSuccess(t *testing.T) {
	cb := decoratorTestBreaker("verifier-half-open")
	inner := common.ChallengeVerifierFunc(func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		return errDependencyFailed
	})
	wrapped := WrapChallengeVerifier(cb, inner)

	// First call fails and opens the breaker (MaxFailures 1).
	require.ErrorIs(t, wrapped(nil, nil, "a", "80", "t", "k"), errDependencyFailed)
	require.Equal(t, StateOpen, cb.State())

	// Second call: ResetTimeout 0 admits it as a half-open probe.
	inner2 := common.ChallengeVerifierFunc(func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		return nil
	})
	wrapped2 := WrapChallengeVerifier(cb, inner2)
	require.NoError(t, wrapped2(nil, nil, "a", "80", "t", "k"))
	assert.Equal(t, StateClosed, cb.State())
}

// --- WrapLogSubmitter ---------------------------------------------------

type fakeLogSubmitter struct {
	sct *ct.SignedCertificateTimestamp
	err error
}

func (f *fakeLogSubmitter) SubmitPrecert(ctx interface{}, precertDER []byte, chain [][]byte, log ct.LogGroup) (*ct.SignedCertificateTimestamp, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.sct, nil
}

func TestWrapLogSubmitter_ClosedDelegatesAndReturnsSCT(t *testing.T) {
	cb := decoratorTestBreaker("ct-closed")
	want := &ct.SignedCertificateTimestamp{}
	submitter := WrapLogSubmitter(cb, &fakeLogSubmitter{sct: want})

	got, err := submitter.SubmitPrecert(context.Background(), nil, nil, ct.LogGroup{URL: "https://ct.example.com"})

	require.NoError(t, err)
	assert.Same(t, want, got)
	assert.Equal(t, StateClosed, cb.State())
}

func TestWrapLogSubmitter_OpenSkipsInnerAndFailsFast(t *testing.T) {
	cb := New(&Config{Name: "ct-open", MaxFailures: 1, ResetTimeout: time.Hour})
	cb.Trip()

	submitter := WrapLogSubmitter(cb, &fakeLogSubmitter{sct: &ct.SignedCertificateTimestamp{}})

	_, err := submitter.SubmitPrecert(context.Background(), nil, nil, ct.LogGroup{URL: "https://ct.example.com"})
	require.ErrorIs(t, err, ErrCircuitOpen)
}

func TestWrapLogSubmitter_HalfOpenProbeClosesOnSuccess(t *testing.T) {
	cb := decoratorTestBreaker("ct-half-open")
	failing := WrapLogSubmitter(cb, &fakeLogSubmitter{err: errDependencyFailed})

	_, err := failing.SubmitPrecert(context.Background(), nil, nil, ct.LogGroup{URL: "https://ct.example.com"})
	require.ErrorIs(t, err, errDependencyFailed)
	require.Equal(t, StateOpen, cb.State())

	recovering := WrapLogSubmitter(cb, &fakeLogSubmitter{sct: &ct.SignedCertificateTimestamp{}})
	_, err = recovering.SubmitPrecert(context.Background(), nil, nil, ct.LogGroup{URL: "https://ct.example.com"})
	require.NoError(t, err)
	assert.Equal(t, StateClosed, cb.State())
}

// --- WrapKMSService -------------------------------------------------------

type fakeKMSService struct {
	err    error
	signer crypto.Signer
}

func (f *fakeKMSService) CreateSigningKey(ctx context.Context, tenantID string, purpose kms.KeyPurpose, algorithm string) (*kms.KeyMetadata, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &kms.KeyMetadata{TenantID: tenantID, Purpose: purpose, Algorithm: algorithm}, nil
}

func (f *fakeKMSService) GetSigningKey(ctx context.Context, tenantID string, purpose kms.KeyPurpose) (crypto.Signer, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.signer, nil
}

func (f *fakeKMSService) ListSigningKeys(ctx context.Context, tenantID string) ([]*kms.KeyMetadata, error) {
	if f.err != nil {
		return nil, f.err
	}
	return nil, nil
}

func (f *fakeKMSService) DeleteSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return f.err
}

func (f *fakeKMSService) EnableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return f.err
}

func (f *fakeKMSService) DisableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return f.err
}

func (f *fakeKMSService) StoreCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose, certDER []byte) error {
	return f.err
}

func (f *fakeKMSService) GetCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []byte("cert"), nil
}

func (f *fakeKMSService) DeleteCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) error {
	return f.err
}

var _ kms.KMSService = (*fakeKMSService)(nil)

func TestWrapKMSService_ClosedDelegatesAndRecordsSuccess(t *testing.T) {
	cb := decoratorTestBreaker("kms-closed")
	svc := WrapKMSService(cb, &fakeKMSService{})

	_, err := svc.GetSigningKey(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA)

	require.NoError(t, err)
	assert.Equal(t, StateClosed, cb.State())
}

func TestWrapKMSService_OpenSkipsInnerAndFailsFast(t *testing.T) {
	cb := New(&Config{Name: "kms-open", MaxFailures: 1, ResetTimeout: time.Hour})
	cb.Trip()

	svc := WrapKMSService(cb, &fakeKMSService{})
	_, err := svc.GetSigningKey(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA)

	require.ErrorIs(t, err, ErrCircuitOpen)
}

func TestWrapKMSService_HalfOpenProbeClosesOnSuccess(t *testing.T) {
	cb := decoratorTestBreaker("kms-half-open")
	failing := WrapKMSService(cb, &fakeKMSService{err: errDependencyFailed})

	_, err := failing.GetSigningKey(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA)
	require.ErrorIs(t, err, errDependencyFailed)
	require.Equal(t, StateOpen, cb.State())

	recovering := WrapKMSService(cb, &fakeKMSService{})
	_, err = recovering.GetSigningKey(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA)
	require.NoError(t, err)
	assert.Equal(t, StateClosed, cb.State())
}
