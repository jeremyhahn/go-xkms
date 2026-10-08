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

	require.NoError(t, second.CredentialService().DeleteCredential(context.Background(), credName))
	_, err = second.CredentialService().RetrieveCredential(context.Background(), credName)
	require.ErrorIs(t, err, credentialspkg.ErrCredentialNotFound)
}

// TestNew_CredentialBarrierStrategy_UnsupportedConfigurationRefusedCleanly
// covers the other half of go-xkms#812: a deployment whose barrier is NOT
// a standalone qrdb node's own (see CredentialsBarrierStrategySupported) has
// no barrier in this process at all, so the credential service can never be
// given a non-nil barrier before resolveConfigSecrets and initializeBackends
// need to consume it -- which is exactly the configuration
// config.Config.Validate() refuses at load time.
//
// Since go-xkms#666, New() itself calls Validate() first, so this exact
// configuration cannot reach initializeCredentialService through New() any
// more -- Validate() now refuses it with a typed *errs.Message naming the
// required shape, before New() touches storage at all (see
// TestNew_CredentialServiceFailure_WrapsAsErrServiceInit for that path).
// What remains to prove here is the backstop initializeCredentialService
// itself still provides: any future caller that reaches it directly, without
// going through New()/Validate(), still fails closed with the credential
// package's own typed nil-barrier error rather than hanging or silently
// proceeding unsealed.
func TestNew_CredentialBarrierStrategy_UnsupportedConfigurationRefusedCleanly(t *testing.T) {
	cfg := &config.Config{
		// A remote datastore has no local node to adopt a barrier from --
		// unlike a local engine choice (memory/file/pebble), which no longer
		// affects node-flip eligibility; only Datastore.Mode does.
		Datastore: config.DatastoreConfig{
			Mode:   "remote",
			Remote: config.DatastoreRemoteConfig{Address: "https://qrdb.example.com:63002", Transport: "rest"},
		},
		Barrier:     config.BarrierConfig{Enabled: true, Strategy: "passphrase"},
		Credentials: config.CredentialsConfig{SealStrategy: "barrier"},
	}
	require.False(t, cfg.CredentialsBarrierStrategySupported(),
		"precondition: a remote datastore never adopts a node barrier")

	s := newMinimalServer(t, cfg)
	err := s.initializeCredentialService()
	require.Error(t, err)
	require.Nil(t, s.credentialService, "a failed initialization must not leave a partial credential service")
	require.ErrorIs(t, err, ErrCredentialServiceFailed)
	require.True(t, errors.Is(err, credentialspkg.ErrNilBarrier),
		"the underlying cause must be the credential package's own typed nil-barrier error")
}
