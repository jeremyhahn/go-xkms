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
	"net"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/ct"
	"github.com/jeremyhahn/go-xkms/pkg/acme/kms"
)

// WrapChallengeVerifier returns a common.ChallengeVerifierFunc that runs fn
// through cb. A verification attempt made while cb is open fails immediately
// with the breaker's own error (ErrCircuitOpen or ErrTooManyRequests) instead
// of reaching the network; this is what keeps a slow or unreachable http-01
// or dns-01 target from holding up every other challenge validation sharing
// the same worker.
func WrapChallengeVerifier(cb *CircuitBreaker, fn common.ChallengeVerifierFunc) common.ChallengeVerifierFunc {
	return func(
		resolver *net.Resolver,
		ca common.CertificateAuthority,
		authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return cb.Execute(func() error {
			return fn(resolver, ca, authzValue, challengePort, challengeToken, expectedKeyAuth)
		})
	}
}

// WrapLogSubmitter returns a ct.LogSubmitter that runs inner.SubmitPrecert
// through cb, so a CT log that stops responding trips the breaker instead of
// blocking every certificate that requires an SCT from it.
func WrapLogSubmitter(cb *CircuitBreaker, inner ct.LogSubmitter) ct.LogSubmitter {
	return &breakerLogSubmitter{cb: cb, inner: inner}
}

type breakerLogSubmitter struct {
	cb    *CircuitBreaker
	inner ct.LogSubmitter
}

// SubmitPrecert implements ct.LogSubmitter.
func (s *breakerLogSubmitter) SubmitPrecert(
	ctx interface{}, precertDER []byte, chain [][]byte, log ct.LogGroup,
) (*ct.SignedCertificateTimestamp, error) {
	goCtx, ok := ctx.(context.Context)
	if !ok {
		goCtx = context.Background()
	}

	var sct *ct.SignedCertificateTimestamp
	err := s.cb.ExecuteContext(goCtx, func() error {
		var submitErr error
		sct, submitErr = s.inner.SubmitPrecert(ctx, precertDER, chain, log)
		return submitErr
	})
	if err != nil {
		return nil, err
	}
	return sct, nil
}

// WrapKMSService returns a kms.KMSService that runs every operation on inner
// through cb, so a KMS backend that stops responding trips the breaker
// instead of hanging every order that needs a tenant signing key.
func WrapKMSService(cb *CircuitBreaker, inner kms.KMSService) kms.KMSService {
	return &breakerKMSService{cb: cb, inner: inner}
}

type breakerKMSService struct {
	cb    *CircuitBreaker
	inner kms.KMSService
}

// CreateSigningKey implements kms.KMSService.
func (s *breakerKMSService) CreateSigningKey(
	ctx context.Context, tenantID string, purpose kms.KeyPurpose, algorithm string,
) (*kms.KeyMetadata, error) {
	var out *kms.KeyMetadata
	err := s.cb.ExecuteContext(ctx, func() error {
		var innerErr error
		out, innerErr = s.inner.CreateSigningKey(ctx, tenantID, purpose, algorithm)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetSigningKey implements kms.KMSService.
func (s *breakerKMSService) GetSigningKey(
	ctx context.Context, tenantID string, purpose kms.KeyPurpose,
) (crypto.Signer, error) {
	var out crypto.Signer
	err := s.cb.ExecuteContext(ctx, func() error {
		var innerErr error
		out, innerErr = s.inner.GetSigningKey(ctx, tenantID, purpose)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListSigningKeys implements kms.KMSService.
func (s *breakerKMSService) ListSigningKeys(ctx context.Context, tenantID string) ([]*kms.KeyMetadata, error) {
	var out []*kms.KeyMetadata
	err := s.cb.ExecuteContext(ctx, func() error {
		var innerErr error
		out, innerErr = s.inner.ListSigningKeys(ctx, tenantID)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteSigningKey implements kms.KMSService.
func (s *breakerKMSService) DeleteSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return s.cb.ExecuteContext(ctx, func() error {
		return s.inner.DeleteSigningKey(ctx, tenantID, keyID)
	})
}

// EnableSigningKey implements kms.KMSService.
func (s *breakerKMSService) EnableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return s.cb.ExecuteContext(ctx, func() error {
		return s.inner.EnableSigningKey(ctx, tenantID, keyID)
	})
}

// DisableSigningKey implements kms.KMSService.
func (s *breakerKMSService) DisableSigningKey(ctx context.Context, tenantID string, keyID string) error {
	return s.cb.ExecuteContext(ctx, func() error {
		return s.inner.DisableSigningKey(ctx, tenantID, keyID)
	})
}

// StoreCertificate implements kms.KMSService.
func (s *breakerKMSService) StoreCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose, certDER []byte) error {
	return s.cb.ExecuteContext(ctx, func() error {
		return s.inner.StoreCertificate(ctx, tenantID, purpose, certDER)
	})
}

// GetCertificate implements kms.KMSService.
func (s *breakerKMSService) GetCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) ([]byte, error) {
	var out []byte
	err := s.cb.ExecuteContext(ctx, func() error {
		var innerErr error
		out, innerErr = s.inner.GetCertificate(ctx, tenantID, purpose)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteCertificate implements kms.KMSService.
func (s *breakerKMSService) DeleteCertificate(ctx context.Context, tenantID string, purpose kms.KeyPurpose) error {
	return s.cb.ExecuteContext(ctx, func() error {
		return s.inner.DeleteCertificate(ctx, tenantID, purpose)
	})
}

// Verify interface compliance.
var _ kms.KMSService = (*breakerKMSService)(nil)
var _ ct.LogSubmitter = (*breakerLogSubmitter)(nil)
