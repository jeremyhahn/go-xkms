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

package objstore

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	xkmsstorage "github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/require"
)

// TestChallengeDAO_DeviceAttestation_SurvivesReload proves the device-attest-01
// binding a validated challenge records (go-xkms#789, go-xkms#828) round-trips
// through the actual ACME DAO encoding, not just through a Go struct held in
// memory: a second Factory/DAO pair is built over the same underlying
// storage.Backend, standing in for a server process reattaching to its store,
// and must read back exactly what the first pair wrote.
func TestChallengeDAO_DeviceAttestation_SurvivesReload(t *testing.T) {
	backend := xkmsstorage.NewMemory()

	kv1, err := kvadapter.New(backend)
	require.NoError(t, err)
	factory1, err := NewFactoryFromKVStore(kv1)
	require.NoError(t, err)

	dao1, err := factory1.(*Factory).ChallengeDAO(1)
	require.NoError(t, err)

	want := &entities.ACMEChallenge{
		ID:        7,
		Type:      "device-attest-01",
		Status:    "valid",
		Token:     "test-token",
		AccountID: 1,
		DeviceAttestation: &entities.DeviceAttestation{
			Format:              "tpm",
			DeviceIdentityType:  "permanent-identifier",
			DeviceIdentityValue: "urn:tpm:device:example-001",
			KeyAuthorization:    "test-token.thumbprint",
			LeafDER:             []byte{0x01, 0x02, 0x03},
			Algorithm:           -7,
			CertInfo:            []byte{0x04, 0x05},
			Signature:           []byte{0x06, 0x07},
			PubArea:             []byte{0x08, 0x09},
		},
	}

	ctx := context.Background()
	require.NoError(t, dao1.Save(ctx, want))

	// A fresh Factory/DAO pair over the SAME backend, not the one that wrote
	// the record: this only passes if DeviceAttestation actually went through
	// the codec, not merely lived on in a pointer the writer still holds.
	kv2, err := kvadapter.New(backend)
	require.NoError(t, err)
	factory2, err := NewFactoryFromKVStore(kv2)
	require.NoError(t, err)
	dao2, err := factory2.(*Factory).ChallengeDAO(1)
	require.NoError(t, err)

	got, err := dao2.Get(ctx, want.ID)
	require.NoError(t, err)
	require.NotNil(t, got.DeviceAttestation)
	require.Equal(t, want.DeviceAttestation, got.DeviceAttestation)
}

// TestChallengeDAO_DeviceAttestation_NilByDefault proves that a challenge
// which never validated through device-attest-01 persists and reloads with no
// DeviceAttestation record at all, so a finalize-time reader can treat a nil
// record as "never bound" rather than a zero-valued one.
func TestChallengeDAO_DeviceAttestation_NilByDefault(t *testing.T) {
	factory := newTestFactory(t)
	dao, err := factory.ChallengeDAO(1)
	require.NoError(t, err)

	want := &entities.ACMEChallenge{
		ID:        1,
		Type:      "http-01",
		Status:    "valid",
		Token:     "test-token",
		AccountID: 1,
	}

	ctx := context.Background()
	require.NoError(t, dao.Save(ctx, want))

	got, err := dao.Get(ctx, want.ID)
	require.NoError(t, err)
	require.Nil(t, got.DeviceAttestation)
}
