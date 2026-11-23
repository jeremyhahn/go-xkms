//go:build codec_json

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

package handlers

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

// denyingVerifier is an operator's verifier: the shipped trust-anchor
// verifier with only the registration confirmation overridden to refuse the
// device. Its denial must stand even when the CSR key and the application
// reference both match the registered record (Codex #2102 round 5).
type denyingVerifier struct {
	*deviceattest01.TrustAnchorVerifier

	mu    sync.Mutex
	calls int
}

func (d *denyingVerifier) ConfirmRegisteredDevice(_ context.Context, _ *deviceattest01.ProvisionedDevice, _ string, _ []byte, _ *x509.Certificate) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return deviceattest01.ErrDeviceNotAuthorized
}

func (d *denyingVerifier) confirmations() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// confirmFinalize builds a service whose device-attest-01 verifier is
// wrap(TrustAnchorVerifier) over a one-record registry that vouches for the
// attested key and application reference, and finalizes a matching DICE
// request against it.
func confirmFinalize(t *testing.T, wrap func(*deviceattest01.TrustAnchorVerifier) deviceattest01.AttestationVerifier) (*entities.Error, *changingRegistry) {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	key := newDICEAliasDeviceKey(t)
	ueid := newTestUeid(t)
	registry := &changingRegistry{records: []*deviceattest01.ProvisionedDevice{
		{DeviceIDKey: marshalSPKI(t, key), ApplicationReference: possessionApplicationEvidence},
	}}
	anchors, err := deviceattest01.NewTrustAnchorVerifier(deviceattest01.TrustAnchors{Devices: registry})
	require.NoError(t, err)
	service.attestingVerifiers = map[string]common.AttestingVerifier{
		common.ChallengeTypeDeviceAttest01: NewDeviceAttestVerifier(wrap(anchors)),
	}

	rec := newDICEDeviceAttestation(t, key, deviceAttestTestKeyAuth, hex.EncodeToString(ueid), ueid)
	rec.LeafDER = newDICEAliasCertMeasuring(t, key, deviceAttestTestKeyAuth, ueid, possessionMeasurements)

	problem := service.bindDeviceAttestationKey(context.Background(), rec, deviceAttestOrder(rec), deviceAttestCSR(t, key, rec))
	return problem, registry
}

func TestBindDeviceAttestationKey_HonoursVerifierConfirmation(t *testing.T) {
	t.Run("an overriding confirmation that denies the device refuses finalization", func(t *testing.T) {
		var denying *denyingVerifier
		problem, registry := confirmFinalize(t, func(anchors *deviceattest01.TrustAnchorVerifier) deviceattest01.AttestationVerifier {
			denying = &denyingVerifier{TrustAnchorVerifier: anchors}
			return denying
		})
		requireProblem(t, problem, common.ErrTypeUnauthorized)
		require.Equal(t, 1, denying.confirmations(), "finalization asks the injected verifier to confirm the device once")
		require.Equal(t, 1, registry.resolves(), "a finalization reads the device registry once")
	})

	t.Run("the trust-anchor verifier confirms on the one registry snapshot", func(t *testing.T) {
		problem, registry := confirmFinalize(t, func(anchors *deviceattest01.TrustAnchorVerifier) deviceattest01.AttestationVerifier {
			return anchors
		})
		require.Nil(t, problem)
		require.Equal(t, 1, registry.resolves(), "a finalization reads the device registry once")
	})
}
