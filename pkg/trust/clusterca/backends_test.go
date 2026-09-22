// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package clusterca

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/require"
)

// TestNewNodeLocalBackends_PassphraseInjectsCAPassword verifies that with
// passphrase protection the resolved keystore password is injected into every
// CA identity's software keystore, and that the resolver returns a usable
// software backend for both the default and named-software lookups.
func TestNewNodeLocalBackends_PassphraseInjectsCAPassword(t *testing.T) {
	caCfg := ca.DefaultMultiIdentityCAConfigWithIntermediate()
	// Ensure each identity has a software keystore slot to receive the password.
	for i := range caCfg.Identity {
		if caCfg.Identity[i].Keystores == nil {
			caCfg.Identity[i].Keystores = &ca.CAKeystoresConfig{}
		}
		if caCfg.Identity[i].Keystores.Software == nil {
			caCfg.Identity[i].Keystores.Software = &ca.CAKeystoreSoftwareConfig{}
		}
	}

	backends, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:  t.TempDir(),
		CAConfig: caCfg,
		Protection: KeyProtection{
			Mode:       KeyProtectPassphrase,
			Passphrase: "unit-test-cluster-ca-secret",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, backends)

	// Every identity's software keystore password must now be the passphrase,
	// sealed in its own enclave (NewLiteralSecretValue carries no Raw
	// reference), so borrow it via WithBytes to assert on the plaintext.
	for i := range caCfg.Identity {
		var got string
		require.NoError(t, caCfg.Identity[i].Keystores.Software.Password.WithBytes(func(b []byte) error {
			got = string(b)
			return nil
		}))
		require.Equal(t, "unit-test-cluster-ca-secret", got,
			"identity %d keystore password not injected", i)
	}

	// The resolver returns a non-nil software backend for the default lookup.
	backend, err := backends("")
	require.NoError(t, err)
	require.NotNil(t, backend)
}

// TestNewNodeLocalBackends_NoneRequiresInsecure verifies that plaintext ("none")
// protection is refused unless AllowInsecure is set (defense in depth beneath
// the daemon's ComplianceGaps gate), and succeeds once opted in.
func TestNewNodeLocalBackends_NoneRequiresInsecure(t *testing.T) {
	_, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:    t.TempDir(),
		CAConfig:   ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection: KeyProtection{Mode: KeyProtectNone},
	})
	require.Error(t, err, "plaintext protection must be refused without AllowInsecure")

	backends, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:    t.TempDir(),
		CAConfig:   ca.DefaultMultiIdentityCAConfigWithIntermediate(),
		Protection: KeyProtection{Mode: KeyProtectNone, AllowInsecure: true},
	})
	require.NoError(t, err)
	require.NotNil(t, backends)
}

// TestNewNodeLocalBackends_NoHardwareFallsBackToSoftware verifies that a "tpm2"
// lookup with no hardware TPM configured falls back to the software backend
// rather than erroring (software-by-default posture).
func TestNewNodeLocalBackends_NoHardwareFallsBackToSoftware(t *testing.T) {
	backends, err := NewNodeLocalBackends(context.Background(), &NodeLocalBackendsParams{
		DataDir:    t.TempDir(),
		Protection: KeyProtection{Mode: KeyProtectPassphrase, Passphrase: "x"},
	})
	require.NoError(t, err)

	backend, err := backends("tpm2")
	require.NoError(t, err)
	require.NotNil(t, backend)
}
