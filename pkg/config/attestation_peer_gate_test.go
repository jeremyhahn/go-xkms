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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

func peerGateTestConfig(mode string) *Config {
	cfg := pivLoginTestConfig()
	cfg.Auth.PIVLogin = nil
	cfg.Attestation = &AttestationConfig{PeerGate: mode}
	return cfg
}

func TestAttestationConfigPeerGateMode(t *testing.T) {
	var unset *AttestationConfig
	mode, err := unset.PeerGateMode()
	require.NoError(t, err)
	assert.Equal(t, peergate.ModeOff, mode, "no attestation section installs no gate")

	mode, err = (&AttestationConfig{PeerGate: "required"}).PeerGateMode()
	require.NoError(t, err)
	assert.Equal(t, peergate.ModeRequired, mode)

	_, err = (&AttestationConfig{PeerGate: "enforce"}).PeerGateMode()
	var modeErr *peergate.ModeError
	assert.ErrorAs(t, err, &modeErr)
}

func TestValidate_PeerGate(t *testing.T) {
	for _, mode := range []string{"", "off", "optional", "required"} {
		assert.NoError(t, peerGateTestConfig(mode).Validate(), "%q", mode)
	}

	err := peerGateTestConfig("enforce").Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "attestation.peer_gate")
	var modeErr *peergate.ModeError
	assert.ErrorAs(t, err, &modeErr)
}

func TestValidate_PeerGateNeedsTheEmbeddedNode(t *testing.T) {
	cfg := peerGateTestConfig("required")
	// The loopback desktop engine is exempt from the unified API server's
	// standalone requirement, so the gate's own check is what rejects it.
	cfg.LoopbackDesktop = true
	cfg.Protocols = ProtocolsConfig{Unix: true}
	cfg.Datastore = DatastoreConfig{Mode: "remote", Remote: DatastoreRemoteConfig{Address: "qrdb:8443", Transport: "grpc"}}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires datastore.mode \"standalone\"")

	cfg.Attestation.PeerGate = "off"
	assert.NoError(t, cfg.Validate(), "no gate, no node needed")
}
