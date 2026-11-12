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

// verdictSubsystem returns the wired subsystem, the caller's tenant and the
// requested device, or ErrNotConfigured.
func (s *XKMSService) verdictSubsystem(ctx context.Context, req *transport.AttestationVerdictRequest) (*continuousAttestation, string, string, error) {
	ca := s.verdicts.load()
	if ca == nil {
		return nil, "", "", ErrNotConfigured
	}
	if req == nil || req.DeviceID == "" {
		return nil, "", "", &continuous.InputError{Field: "device ID", Cause: errors.New("is empty")}
	}
	return ca, callerTenant(ctx), req.DeviceID, nil
}

// ListAttestationVerdicts returns the device's verdicts, oldest first.
func (s *XKMSService) ListAttestationVerdicts(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.ListAttestationVerdictsResponse, error) {
	ca, tenant, deviceID, err := s.verdictSubsystem(ctx, req)
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
	ca, tenant, deviceID, err := s.verdictSubsystem(ctx, req)
	if err != nil {
		return nil, err
	}
	return ca.store.LatestVerdict(ctx, tenant, deviceID)
}

// ReattestDevice re-attests the device now and returns the stored verdict.
func (s *XKMSService) ReattestDevice(ctx context.Context, req *transport.AttestationVerdictRequest) (*transport.AttestationVerdict, error) {
	ca, tenant, deviceID, err := s.verdictSubsystem(ctx, req)
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
