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

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
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

// validationVerifier returns a challenge verifier that fetches the challenge
// URL through client, the way the http-01 verifier does, and returns the
// client's error unchanged.
func validationVerifier(client *validation.Client) common.ChallengeVerifierFunc {
	return func(_ *net.Resolver, _ common.CertificateAuthority, authzValue, challengePort, challengeToken, _ string) error {
		_, err := client.Get(context.Background(), validation.Target{
			Host: authzValue,
			Port: challengePort,
			Path: "/.well-known/acme-challenge/" + challengeToken,
		})
		return err
	}
}

// closedLoopbackPort returns a loopback port nothing listens on, so a
// connection to it fails the way an unreachable public target does.
func closedLoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	return port
}

// TestWrapChallengeVerifier_RefusedTargetsDoNotOpenBreaker is the regression
// test for #1181: an ACME account naming reserved or invalid targets must not
// be able to open the shared http-01 breaker for every other account.
func TestWrapChallengeVerifier_RefusedTargetsDoNotOpenBreaker(t *testing.T) {
	cb := decoratorTestBreaker("verifier-refused-flood")
	wrapped := WrapChallengeVerifier(cb, validationVerifier(validation.NewClient(validation.Config{})))

	targets := []struct{ host, port string }{
		{"127.0.0.1", "80"},
		{"10.0.0.1", "80"},
		{"169.254.169.254", "80"},
		{"::1", "80"},
		{"169.254.169.254/latest/meta-data", "80"},
		{"example.com", "0"},
	}
	for i := 0; i < 50; i++ {
		target := targets[i%len(targets)]
		err := wrapped(nil, nil, target.host, target.port, "token", "keyauth")
		require.Error(t, err)
		require.True(t, validation.IsTargetRejected(err), "target %s:%s: got %v, want the client's refusal", target.host, target.port, err)
	}

	assert.Equal(t, StateClosed, cb.State(), "refused targets must not open the breaker (MaxFailures 1)")
	failures, _ := cb.Counts()
	assert.Zero(t, failures)
}

// TestWrapChallengeVerifier_ConnectionFailuresOpenBreaker verifies the
// breaker still does its job: targets the client contacts and cannot reach
// count as failures.
func TestWrapChallengeVerifier_ConnectionFailuresOpenBreaker(t *testing.T) {
	cb := New(&Config{Name: "verifier-connection", MaxFailures: 3, ResetTimeout: time.Hour})
	wrapped := WrapChallengeVerifier(cb, validationVerifier(validation.NewClient(validation.Config{AllowPrivateTargets: true})))
	port := closedLoopbackPort(t)

	for i := 0; i < 3; i++ {
		err := wrapped(nil, nil, "127.0.0.1", port, "token", "keyauth")
		var verr *validation.Error
		require.ErrorAs(t, err, &verr)
		require.Equal(t, validation.KindConnection, verr.Kind)
	}

	assert.Equal(t, StateOpen, cb.State())
	require.ErrorIs(t, wrapped(nil, nil, "127.0.0.1", port, "token", "keyauth"), ErrCircuitOpen)
}

// TestWrapChallengeVerifier_RefusalsDoNotMaskConnectionFailures verifies that
// refusals are neutral rather than successes: interleaving them with genuine
// connection failures must not reset the failure count and hold an
// unreachable-network breaker closed.
func TestWrapChallengeVerifier_RefusalsDoNotMaskConnectionFailures(t *testing.T) {
	cb := New(&Config{Name: "verifier-interleaved", MaxFailures: 2, ResetTimeout: time.Hour})
	contacted := WrapChallengeVerifier(cb, validationVerifier(validation.NewClient(validation.Config{AllowPrivateTargets: true})))
	refusing := WrapChallengeVerifier(cb, validationVerifier(validation.NewClient(validation.Config{})))
	port := closedLoopbackPort(t)

	require.Error(t, contacted(nil, nil, "127.0.0.1", port, "token", "keyauth"))
	require.True(t, validation.IsTargetRejected(refusing(nil, nil, "127.0.0.1", port, "token", "keyauth")))
	require.Error(t, contacted(nil, nil, "127.0.0.1", port, "token", "keyauth"))

	assert.Equal(t, StateOpen, cb.State())
}

// --- WrapLogSubmitter ---------------------------------------------------

type fakeLogSubmitter struct {
	sct *ct.SignedCertificateTimestamp
	err error
}

func (f *fakeLogSubmitter) SubmitPrecert(ctx context.Context, precertDER []byte, chain [][]byte, log ct.LogGroup) (*ct.SignedCertificateTimestamp, error) {
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

// TestWrapKMSService_RemainingMethodsDelegateThroughBreaker exercises every
// breakerKMSService method beyond CreateSigningKey/GetSigningKey, both
// delegating successfully in the closed state and failing fast while the
// breaker is open, so each method's own ExecuteContext wiring -- not just the
// pattern shared with GetSigningKey -- is under test.
func TestWrapKMSService_RemainingMethodsDelegateThroughBreaker(t *testing.T) {
	tests := []struct {
		name string
		call func(svc kms.KMSService) error
	}{
		{
			name: "CreateSigningKey",
			call: func(svc kms.KMSService) error {
				_, err := svc.CreateSigningKey(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA, "ECDSA-P256")
				return err
			},
		},
		{
			name: "ListSigningKeys",
			call: func(svc kms.KMSService) error {
				_, err := svc.ListSigningKeys(context.Background(), "tenant-a")
				return err
			},
		},
		{
			name: "DeleteSigningKey",
			call: func(svc kms.KMSService) error {
				return svc.DeleteSigningKey(context.Background(), "tenant-a", "key-1")
			},
		},
		{
			name: "EnableSigningKey",
			call: func(svc kms.KMSService) error {
				return svc.EnableSigningKey(context.Background(), "tenant-a", "key-1")
			},
		},
		{
			name: "DisableSigningKey",
			call: func(svc kms.KMSService) error {
				return svc.DisableSigningKey(context.Background(), "tenant-a", "key-1")
			},
		},
		{
			name: "StoreCertificate",
			call: func(svc kms.KMSService) error {
				return svc.StoreCertificate(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA, []byte("der"))
			},
		},
		{
			name: "GetCertificate",
			call: func(svc kms.KMSService) error {
				_, err := svc.GetCertificate(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA)
				return err
			},
		},
		{
			name: "DeleteCertificate",
			call: func(svc kms.KMSService) error {
				return svc.DeleteCertificate(context.Background(), "tenant-a", kms.KeyPurposeTenantIntermediateCA)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/closed delegates and succeeds", func(t *testing.T) {
			cb := decoratorTestBreaker("kms-" + tt.name + "-closed")
			svc := WrapKMSService(cb, &fakeKMSService{})

			err := tt.call(svc)

			require.NoError(t, err)
			assert.Equal(t, StateClosed, cb.State())
		})

		t.Run(tt.name+"/open fails fast without reaching inner", func(t *testing.T) {
			cb := New(&Config{Name: "kms-" + tt.name + "-open", MaxFailures: 1, ResetTimeout: time.Hour})
			cb.Trip()
			svc := WrapKMSService(cb, &fakeKMSService{err: errDependencyFailed})

			err := tt.call(svc)

			require.ErrorIs(t, err, ErrCircuitOpen)
		})
	}
}
