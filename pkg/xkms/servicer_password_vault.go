// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// The personal vault (pkg/staticpw vault.go) on the service layer. Every
// method acts on the caller's own vault -- the tenant and subject of the
// identity on ctx -- and never on another user's. A request without an
// identity is served by the unscoped system store, which has no vault, so it
// gets ErrOperationNotSupported.

// vaultCaller returns the password manager and the caller's tenant and
// subject for a vault operation.
func (s *XKMSService) vaultCaller(ctx context.Context) (*staticpw.TenantPasswordStoreManager, string, string, error) {
	manager := s.passwordStoreManager.load()
	if manager == nil {
		if s.passwordStore.load() == nil {
			return nil, "", "", ErrNotConfigured
		}
		return nil, "", "", ErrOperationNotSupported
	}
	tenantID, subject, ok := passwordCaller(ctx)
	if !ok {
		return nil, "", "", ErrOperationNotSupported
	}
	return manager, tenantID, subject, nil
}

// VaultCredentialSealError is returned when a transport credential's secret
// cannot be sealed into protected memory.
type VaultCredentialSealError struct {
	Err error
}

// Error returns a human-readable description.
func (e *VaultCredentialSealError) Error() string {
	return "keystore: failed to seal vault credential secret: " + e.Err.Error()
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *VaultCredentialSealError) Unwrap() error { return e.Err }

// vaultCredential converts a transport credential. The secret bytes are
// copied and sealed into protected memory, so the caller's request may be
// zeroed independently. An empty secret is left nil: staticpw's own
// validation rejects it with the right sentinel for the factor type.
func vaultCredential(c transport.PasswordVaultCredential) (staticpw.VaultCredential, error) {
	cred := staticpw.VaultCredential{
		Type:           staticpw.FactorType(c.Factor),
		CredentialID:   c.CredentialID,
		PRFSalt:        c.PRFSalt,
		Label:          c.Label,
		RelyingParty:   c.RPID,
		PublicKey:      c.PublicKey,
		Certificate:    c.Certificate,
		KeyFingerprint: c.KeyFingerprint,
		KeyRef: staticpw.VaultKeyRef{
			Backend:   c.KeyRef.Backend,
			KeyID:     c.KeyRef.KeyID,
			TPMPolicy: c.KeyRef.TPMPolicy,
		},
	}
	var secretBytes []byte
	switch {
	case cred.Type == staticpw.FactorPassphrase:
		secretBytes = []byte(c.Passphrase)
	case cred.Type == staticpw.FactorPasskey, cred.Type.IsKeyFactor():
		secretBytes = append([]byte(nil), c.Secret...)
	}
	if len(secretBytes) == 0 {
		return cred, nil
	}
	secret, err := secure.NewSecret(secretBytes)
	if err != nil {
		return staticpw.VaultCredential{}, &VaultCredentialSealError{Err: err}
	}
	cred.Secret = secret
	return cred, nil
}

// vaultFactor converts a factor description.
func vaultFactor(f staticpw.VaultFactorInfo) transport.PasswordVaultFactor {
	return transport.PasswordVaultFactor{
		ID:           f.ID,
		Factor:       string(f.Type),
		Label:        f.Label,
		CreatedAt:    f.CreatedAt.Format(time.RFC3339),
		CredentialID: f.CredentialID,
		PRFSalt:      f.PRFSalt,
		RPID:         f.RelyingParty,

		KeyFingerprint: f.KeyFingerprint,
		KeyAlgorithm:   f.KeyAlgorithm,
		KeyChallenge:   f.KeyChallenge,
		KeyCheck:       f.KeyCheck,
		KeyRef: transport.PasswordVaultKeyRef{
			Backend:   f.KeyRef.Backend,
			KeyID:     f.KeyRef.KeyID,
			TPMPolicy: f.KeyRef.TPMPolicy,
		},
		CertificateSubject: f.CertificateSubject,
	}
}

// enrollResponse converts an enrollment result.
func enrollResponse(res *staticpw.EnrollResult) *transport.PasswordVaultEnrollResponse {
	return &transport.PasswordVaultEnrollResponse{Factor: vaultFactor(res.Factor), RecoveryCode: res.RecoveryCode}
}

// PasswordVaultStatus reports whether the caller's vault has a factor,
// whether the caller's session is open, and the enrolled factors -- a
// passkey's credential ID and PRF salt are what a client needs to evaluate
// hmac-secret before unlocking.
func (s *XKMSService) PasswordVaultStatus(ctx context.Context) (*transport.PasswordVaultStatusResponse, error) {
	manager, tenantID, subject, err := s.vaultCaller(ctx)
	if err != nil {
		return nil, err
	}
	status, err := manager.VaultStatus(ctx, tenantID, subject)
	if err != nil {
		return nil, err
	}
	resp := &transport.PasswordVaultStatusResponse{
		Initialized: status.Initialized,
		Unlocked:    status.Unlocked,
		Factors:     make([]transport.PasswordVaultFactor, 0, len(status.Factors)),
		PasskeyRPID: status.PasskeyRelyingParty,
	}
	for _, f := range status.Factors {
		resp.Factors = append(resp.Factors, vaultFactor(f))
	}
	return resp, nil
}

// PasswordVaultEnroll enrolls a passphrase or passkey. The first enrollment
// initializes the caller's vault and returns the one-time recovery code;
// later enrollments need the caller's session open.
func (s *XKMSService) PasswordVaultEnroll(ctx context.Context, req *transport.PasswordVaultEnrollRequest) (*transport.PasswordVaultEnrollResponse, error) {
	manager, tenantID, subject, err := s.vaultCaller(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	cred, err := vaultCredential(req.PasswordVaultCredential)
	if err != nil {
		return nil, err
	}
	defer cred.Secret.Destroy()
	res, err := manager.EnrollFactor(ctx, tenantID, subject, cred)
	if err != nil {
		return nil, err
	}
	return enrollResponse(res), nil
}

// PasswordVaultRotate re-wraps the caller's DEK under a new secret for
// factor req.FactorID, of the same type; the old secret stops working. The
// DEK itself never changes. The caller's session must be open.
func (s *XKMSService) PasswordVaultRotate(ctx context.Context, req *transport.PasswordVaultRotateRequest) (*transport.PasswordVaultEnrollResponse, error) {
	manager, tenantID, subject, err := s.vaultCaller(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	cred, err := vaultCredential(req.PasswordVaultCredential)
	if err != nil {
		return nil, err
	}
	defer cred.Secret.Destroy()
	res, err := manager.RotateFactor(ctx, tenantID, subject, req.FactorID, cred)
	if err != nil {
		return nil, err
	}
	return enrollResponse(res), nil
}

// PasswordVaultRemoveFactor removes factor req.FactorID. The caller's session
// must be open; the recovery code and the last passphrase or passkey cannot
// be removed.
func (s *XKMSService) PasswordVaultRemoveFactor(ctx context.Context, req *transport.PasswordVaultRemoveFactorRequest) error {
	manager, tenantID, subject, err := s.vaultCaller(ctx)
	if err != nil {
		return err
	}
	if req == nil {
		return ErrNilRequest
	}
	return manager.RemoveFactor(ctx, tenantID, subject, req.FactorID)
}

// PasswordVaultRecover uses the caller's one-time recovery code to enroll a
// new passphrase or passkey, replaces the code with a new one (returned,
// shown once) and opens the session.
func (s *XKMSService) PasswordVaultRecover(ctx context.Context, req *transport.PasswordVaultRecoverRequest) (*transport.PasswordVaultEnrollResponse, error) {
	manager, tenantID, subject, err := s.vaultCaller(ctx)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrNilRequest
	}
	cred, err := vaultCredential(req.PasswordVaultCredential)
	if err != nil {
		return nil, err
	}
	defer cred.Secret.Destroy()
	code := []byte(req.RecoveryCode)
	defer clear(code)
	res, err := manager.RecoverVault(ctx, tenantID, subject, code, cred)
	if err != nil {
		return nil, err
	}
	return enrollResponse(res), nil
}
