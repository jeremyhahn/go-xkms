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

package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestCredentialBarrierStrategy_RoundTripsAcrossRestart is the go-xkms#812
// regression: credentials.seal_strategy "barrier" is only satisfiable when
// this deployment's barrier IS the qrdb node's own (see
// config.Config.CredentialsBarrierStrategySupported). In that configuration
// the node barrier is adopted (initEmbeddedQRDBNode, inside
// initializeQRDBStorage) before initializeCredentialService ever runs, so
// the credential service's "barrier" strategy has a non-nil, unsealed
// barrier from the moment it is constructed -- a credential stored through
// it survives a restart exactly the way the barrier-encrypted data plane
// does (see TestNodeSealFlip_EncryptsDataPlaneAtRest).
func TestCredentialBarrierStrategy_RoundTripsAcrossRestart(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:  true,
		Strategy: "none", // auto-unseals unattended; no operator step in a test
	}
	cfg.Credentials = config.CredentialsConfig{SealStrategy: "barrier"}
	require.True(t, cfg.CredentialsBarrierStrategySupported(),
		"precondition: this shape must be the one Validate() admits")

	const credName = "pkcs11-user-pin"
	credValue := []byte("s3cr3t-user-pin")

	// First boot: store the credential through the barrier-backed service.
	first, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, first.CredentialService())
	require.Equal(t, "barrier", first.CredentialService().Strategy())

	require.NoError(t, first.CredentialService().StoreCredential(context.Background(), credName, credValue))
	got, err := first.CredentialService().RetrieveCredential(context.Background(), credName)
	require.NoError(t, err)
	require.Equal(t, credValue, got, "credential must read back within the same boot")

	require.NoError(t, first.Shutdown())

	// Restart against the same data directory: the SAME config.Config (and
	// therefore the same Storage.Path) is handed to a second New(), exactly
	// as an operator restarting xkmsd would.
	xkms.Reset()
	second, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = second.Shutdown() }()

	require.NotNil(t, second.CredentialService())
	roundTripped, err := second.CredentialService().RetrieveCredential(context.Background(), credName)
	require.NoError(t, err, "credential stored under the barrier strategy must survive a restart")
	require.Equal(t, credValue, roundTripped)
}

// TestNew_CredentialBarrierStrategy_UnsupportedConfigurationRefusedCleanly
// covers the other half of go-xkms#812: a deployment whose barrier is NOT
// the qrdb node's own (see CredentialsBarrierStrategySupported) can never
// give the credential service a non-nil barrier before resolveConfigSecrets
// and initializeBackends need to consume it -- the general (non-node) xkms
// barrier is itself built from already-initialized backends
// (buildHardwareSealStrategies), which is exactly the cycle
// config.Config.Validate() now refuses at load time. An embedded caller
// that constructs *config.Config by hand and skips Validate() must still
// fail closed here, with a typed error and no partial credential service,
// rather than hang or silently proceed unsealed.
func TestNew_CredentialBarrierStrategy_UnsupportedConfigurationRefusedCleanly(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t) // Storage.Backend == "file": never node-flip-wired
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "passphrase"}
	cfg.Credentials = config.CredentialsConfig{SealStrategy: "barrier"}
	require.False(t, cfg.CredentialsBarrierStrategySupported(),
		"precondition: file storage never adopts a node barrier")

	srv, err := New(cfg)
	require.Nil(t, srv, "a failed construction must not hand back a partially-built server")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrCredentialServiceFailed)
	require.True(t, errors.Is(err, credentialspkg.ErrNilBarrier),
		"the underlying cause must be the credential package's own typed nil-barrier error")
}
