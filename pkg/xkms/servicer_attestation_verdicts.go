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

package xkms

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/continuous"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// continuousAttestation pairs the re-attestation engine with the store its
// verdicts are read from.
type continuousAttestation struct {
	engine *continuous.Engine
	store  *continuous.Store
}

// SetContinuousAttestation wires the verdict verbs. A nil store leaves them
// unconfigured; a store without an engine serves the stored verdicts but
// cannot re-attest.
func (s *XKMSService) SetContinuousAttestation(engine *continuous.Engine, store *continuous.Store) {
	if store == nil {
		s.verdicts.store(nil)
		return
	}
	s.verdicts.store(&continuousAttestation{engine: engine, store: store})
}

// SetDefaultContinuousAttestation serves the verdicts of store, without an
// engine, only when no subsystem is wired yet; it reports whether it did. A
// pair a host configured with SetContinuousAttestation is never replaced, so
// its engine keeps answering ReattestDevice. The check and the store are one
// atomic step.
func (s *XKMSService) SetDefaultContinuousAttestation(store *continuous.Store) bool {
	if store == nil {
		return false
	}
	next := &continuousAttestation{store: store}
	for {
		cur := s.verdicts.ref.Load()
		if cur != nil && *cur != nil {
			return false
		}
		if s.verdicts.ref.CompareAndSwap(cur, &next) {
			return true
		}
	}
}

// verdictSubsystem returns the wired subsystem, the caller's tenant and the
// requested device, or ErrNotConfigured.
func (s *XKMSService) verdictSubsystem(ctx context.Context, action string, req *transport.AttestationVerdictRequest) (*continuousAttestation, string, string, error) {
	// The permission is checked first: a refused caller never reaches the
	// verdict subsystem, nor learns whether it is configured.
	if err := s.AuthorizeCaller(ctx, auth.ResourceAttestationVerdicts, action); err != nil {
		return nil, "", "", &VerdictPermissionError{Permission: auth.ResourceAttestationVerdicts + ":" + action, Err: err}
	}
	ca := s.verdicts.load()
	if ca == nil {
		return nil, "", "", ErrNotConfigured
	}
	if req == nil || req.DeviceID == "" {
		return nil, "", "", &continuous.InputError{Field: "device ID", Cause: errors.New("is empty")}
	}
	return ca, callerTenant(ctx), req.DeviceID, nil
}

// VerdictPermissionError refuses a verdict call by a caller without the
// permission it requires. It matches the authorizer's refusal under
// errors.Is.
type VerdictPermissionError struct {
	// Permission is the resource:action the call requires.
	Permission string
	// Err is the authorizer's refusal.
	Err error
}

// Error reports the permission and the refusal.
func (e *VerdictPermissionError) Error() string {
	return "attestation: the verdict call requires " + e.Permission + ": " + e.Err.Error()
}

// Unwrap returns the authorizer's refusal.
func (e *VerdictPermissionError) Unwrap() error { return e.Err }

// ListAttestationVerdicts returns the device's verdicts, oldest first.
func (s *XKMSService) ListAttestationVerdicts(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.ListAttestationVerdictsResponse, error) {
	ca, tenant, deviceID, err := s.verdictSubsystem(ctx, auth.ActionList, req)
	if err != nil {
		return nil, err
	}
	verdicts, err := ca.store.ListVerdicts(ctx, tenant, deviceID)
	if err != nil {
		return nil, err
	}
	return &transport.ListAttestationVerdictsResponse{Verdicts: verdicts}, nil
}

// GetLatestAttestationVerdict returns the device's newest verdict, or a
// *continuous.VerdictNotFoundError.
func (s *XKMSService) GetLatestAttestationVerdict(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	ca, tenant, deviceID, err := s.verdictSubsystem(ctx, auth.ActionGet, req)
	if err != nil {
		return nil, err
	}
	return ca.store.LatestVerdict(ctx, tenant, deviceID)
}

// ReattestDevice re-attests the device now and returns the stored verdict.
func (s *XKMSService) ReattestDevice(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	ca, tenant, deviceID, err := s.verdictSubsystem(ctx, auth.ActionCreate, req)
	if err != nil {
		return nil, err
	}
	if ca.engine == nil {
		return nil, ErrNotConfigured
	}
	v, err := ca.engine.Reattest(ctx, tenant, deviceID)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
