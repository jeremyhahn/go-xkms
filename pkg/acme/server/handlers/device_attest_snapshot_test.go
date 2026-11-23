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
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// changingRegistry is a device registry whose record for a device changes
// while a finalization reads it: the first resolve returns records[0], every
// later one the last record.
type changingRegistry struct {
	mu      sync.Mutex
	records []*deviceattest01.ProvisionedDevice
	calls   int
}

func (r *changingRegistry) ResolveDevice(_ context.Context, _ string) (*deviceattest01.ProvisionedDevice, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.records[min(r.calls, len(r.records)-1)]
	r.calls++
	return record, nil
}

func (r *changingRegistry) resolves() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// TestBindDeviceAttestationKey_OneRegistrySnapshot is #2102's round-4 P1: the
// possession request carries application evidence A and the alias leaf
// evidence B, and the device's registered reference moves from A to B while
// the finalization reads the registry. No one record authorizes both, so the
// request is refused, and the registry is read once per finalization.
func TestBindDeviceAttestationKey_OneRegistrySnapshot(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)

	evidenceA := bytes.Clone(possessionApplicationEvidence)
	evidenceB := bytes.Clone(evidenceA)
	evidenceB[len(evidenceB)-1] ^= 0xff
	measurementsB := bytes.Replace(possessionMeasurements, evidenceA, evidenceB, 1)
	require.NotEqual(t, possessionMeasurements, measurementsB)

	key := newDICEAliasDeviceKey(t)
	ueid := newTestUeid(t)
	registry := &changingRegistry{records: []*deviceattest01.ProvisionedDevice{
		{DeviceIDKey: marshalSPKI(t, key), ApplicationReference: evidenceA},
		{DeviceIDKey: marshalSPKI(t, key), ApplicationReference: evidenceB},
	}}
	verifier, err := deviceattest01.NewTrustAnchorVerifier(deviceattest01.TrustAnchors{Devices: registry})
	require.NoError(t, err)
	service.attestingVerifiers = map[string]common.AttestingVerifier{
		common.ChallengeTypeDeviceAttest01: NewDeviceAttestVerifier(verifier),
	}

	rec := newDICEDeviceAttestation(t, key, deviceAttestTestKeyAuth, hex.EncodeToString(ueid), ueid)
	rec.LeafDER = newDICEAliasCertMeasuring(t, key, deviceAttestTestKeyAuth, ueid, measurementsB)

	problem := service.bindDeviceAttestationKey(context.Background(), rec, deviceAttestOrder(rec), deviceAttestCSR(t, key, rec))
	requireProblem(t, problem, common.ErrTypeUnauthorized)
	require.Equal(t, 1, registry.resolves(), "a finalization reads the device registry once")
}
