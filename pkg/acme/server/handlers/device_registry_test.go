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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
)

// deviceRegistry is the device registry these tests provision: provisioning
// records keyed by the lowercase hex UEID, the way the injected resolver keys
// them (go-xkms#1441).
type deviceRegistry map[string]*deviceattest01.ProvisionedDevice

func (r deviceRegistry) ResolveDevice(_ context.Context, ueid string) (*deviceattest01.ProvisionedDevice, error) {
	record, ok := r[ueid]
	if !ok {
		return nil, deviceattest01.ErrDeviceNotProvisioned
	}
	return record, nil
}

// registeredDevices is the production TrustAnchorVerifier over a registry the
// test still holds, so a test can withdraw or re-key a device after its
// challenge.
type registeredDevices struct {
	*deviceattest01.TrustAnchorVerifier
	registry deviceRegistry
}

func newRegisteredDevices(t *testing.T) *registeredDevices {
	t.Helper()
	registry := deviceRegistry{}
	verifier, err := deviceattest01.NewTrustAnchorVerifier(deviceattest01.TrustAnchors{Devices: registry})
	require.NoError(t, err)
	return &registeredDevices{TrustAnchorVerifier: verifier, registry: registry}
}

// provision records key as the DeviceID key of the device whose UEID is ueid.
func (r *registeredDevices) provision(t *testing.T, ueid []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	r.registry[hex.EncodeToString(ueid)] = &deviceattest01.ProvisionedDevice{DeviceIDKey: marshalSPKI(t, key)}
}

// withdraw removes the device whose UEID is ueid from the registry.
func (r *registeredDevices) withdraw(ueid []byte) {
	delete(r.registry, hex.EncodeToString(ueid))
}

// serviceRegistry returns the registry service's device-attest-01 verifier
// resolves against, wiring one in when the service has none.
func serviceRegistry(t *testing.T, service *RestService) *registeredDevices {
	t.Helper()
	if registered, ok := service.deviceAttestationVerifier().(*registeredDevices); ok {
		return registered
	}
	registered := newRegisteredDevices(t)
	if service.attestingVerifiers == nil {
		service.attestingVerifiers = make(map[string]common.AttestingVerifier)
	}
	service.attestingVerifiers[common.ChallengeTypeDeviceAttest01] = NewDeviceAttestVerifier(registered)
	return registered
}

// newTestUeid is a random-type UEID: 0x01 followed by a 16-byte DeviceID.
func newTestUeid(t *testing.T) []byte {
	t.Helper()
	ueid := make([]byte, 17)
	ueid[0] = 0x01
	_, err := rand.Read(ueid[1:])
	require.NoError(t, err)
	return ueid
}

func marshalSPKI(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return spki
}
