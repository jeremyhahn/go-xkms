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

package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// validNoisePublicKeyForTest and validLocalNoisePrivateKeyForTest return a
// random 32-byte Noise key (base64), for NoisePublicKey and
// LocalNoisePrivateKey respectively. Every 32-byte string is an X25519
// private key and a well-formed public key, and resolveListenTargetDevice
// only decodes each field on its own, so the fixture runs no X25519: that
// keeps these tests about device resolution under GODEBUG=fips140=only,
// where crypto/ecdh refuses X25519.
func validNoisePublicKeyForTest(t *testing.T) string {
	t.Helper()
	return randomNoiseKeyForTest(t)
}

func validLocalNoisePrivateKeyForTest(t *testing.T) string {
	t.Helper()
	return randomNoiseKeyForTest(t)
}

func randomNoiseKeyForTest(t *testing.T) string {
	t.Helper()
	key := make([]byte, bootstrap.NoiseKeySize)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(key)
}

// --- allowPhoneSyncExport ---

// TestAllowPhoneSyncExport_ProjectsTheTwoPlanes exercises the whole
// resolution table (go-xkms#1306), mirroring
// TestAllowUnattestablePairing_ProjectsTheUserPlane's shape for the sibling
// decision: session governs unless a verified, locking policy overrides it.
func TestAllowPhoneSyncExport_ProjectsTheTwoPlanes(t *testing.T) {
	unlocked := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicyUnsealed}
	lockedOpen := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicySealedVerified, Policy: xkeyconfig.PolicySection{
		LockPhoneSyncPolicy:        true,
		PhoneSyncAllowSecretExport: true,
	}}
	lockedClosed := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicySealedVerified, Policy: xkeyconfig.PolicySection{
		LockPhoneSyncPolicy:        true,
		PhoneSyncAllowSecretExport: false,
	}}
	unverifiedButWouldAllow := &xkeyconfig.VerifiedPolicy{State: xkeyconfig.PolicySealedVerified, Policy: xkeyconfig.PolicySection{
		LockPhoneSyncPolicy:        false,
		PhoneSyncAllowSecretExport: true,
	}}

	tests := []struct {
		name           string
		sessionAllowed bool
		policy         *xkeyconfig.VerifiedPolicy
		want           bool
		why            string
	}{
		{name: "no policy, session declines", sessionAllowed: false, policy: nil, want: false,
			why: "an unknown enterprise plane fails closed, matching the session's own refusal"},
		{name: "no policy, session allows", sessionAllowed: true, policy: nil, want: true,
			why: "with no policy to consult, the operator's own --allow-sync governs"},
		{name: "unlocked policy, session declines", sessionAllowed: false, policy: unlocked, want: false},
		{name: "unlocked policy, session allows", sessionAllowed: true, policy: unlocked, want: true,
			why: "unlocked, the session's own choice is the answer"},
		{name: "locked open, session declines", sessionAllowed: false, policy: lockedOpen, want: true,
			why: "locked open overrides a session that did not opt in"},
		{name: "locked closed, session allows", sessionAllowed: true, policy: lockedClosed, want: false,
			why: "locked closed overrides --allow-sync"},
		{name: "not locked despite PhoneSyncAllowSecretExport set, session declines", sessionAllowed: false, policy: unverifiedButWouldAllow, want: false,
			why: "LockPhoneSyncPolicy false means the field is not consulted regardless of its value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allowPhoneSyncExport(tt.sessionAllowed, tt.policy)
			assert.Equal(t, tt.want, got, tt.why)
		})
	}
}

// --- newSessionSyncApproval ---

func TestNewSessionSyncApproval_AllowedGrantsEveryRequest(t *testing.T) {
	approve := newSessionSyncApproval("Pixel", true, discardLogger())

	err := approve(context.Background(), &pairing.SyncApprovalRequest{Method: pairingproto.MethodRemoteSyncPasswords, DeviceName: "Pixel"})

	assert.NoError(t, err)
}

func TestNewSessionSyncApproval_NotAllowedRefusesWithErrSyncNotApproved(t *testing.T) {
	approve := newSessionSyncApproval("Pixel", false, discardLogger())

	err := approve(context.Background(), &pairing.SyncApprovalRequest{Method: pairingproto.MethodRemoteSyncOATH, DeviceName: "Pixel"})

	require.Error(t, err)
	assert.ErrorIs(t, err, pairingproto.ErrSyncNotApproved)
}

// --- resolveListenTargetDevice ---

func TestResolveListenTargetDevice_SingleDeviceAutoSelects(t *testing.T) {
	cfg := &DevicesConfig{Devices: []PairedDevice{{
		Name: "Solo", Address: "11:22:33:44:55:66",
		NoisePublicKey:       validNoisePublicKeyForTest(t),
		LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
	}}}

	device, remoteStatic, localKey, err := resolveListenTargetDevice(cfg, "", nil, discardLogger())
	require.NoError(t, err)
	defer localKey.Destroy()

	assert.Equal(t, "Solo", device.Name)
	assert.Len(t, remoteStatic, bootstrap.NoiseKeySize)
}

func TestResolveListenTargetDevice_UnknownFilterReportsNotFound(t *testing.T) {
	cfg := &DevicesConfig{Devices: []PairedDevice{{
		Name: "Solo", Address: "11:22:33:44:55:66",
		NoisePublicKey:       validNoisePublicKeyForTest(t),
		LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
	}}}

	_, _, _, err := resolveListenTargetDevice(cfg, "Nonexistent", nil, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestResolveListenTargetDevice_MultipleWithNoDefaultRequiresDisambiguation(t *testing.T) {
	cfg := &DevicesConfig{Devices: []PairedDevice{
		{Name: "A", Address: "11:22:33:44:55:66", NoisePublicKey: validNoisePublicKeyForTest(t), LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t)},
		{Name: "B", Address: "AA:BB:CC:DD:EE:FF", NoisePublicKey: validNoisePublicKeyForTest(t), LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t)},
	}}

	_, _, _, err := resolveListenTargetDevice(cfg, "", nil, discardLogger())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNoDefaultDevice)
}
