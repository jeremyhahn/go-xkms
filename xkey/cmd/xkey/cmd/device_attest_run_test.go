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

//go:build ble

package cmd

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// runAttestWithPhone pairs a device, answers local.attestKey through the
// given transport and returns the command's stdout and error.
func runAttestWithPhone(t *testing.T, transport *fakeDeviceTransport, noVerify bool) (string, error) {
	t.Helper()
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	useFakeTransport(t, transport)

	cmd := deviceAttestTestCmd()
	if noVerify {
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "no-verify", "true"))
	}

	var err error
	out := captureDeviceInfoStdout(t, func() {
		err = runDeviceAttest(cmd, []string{"signing-key"})
	})
	return out, err
}

// attestResultTransport answers local.attestKey with result.
func attestResultTransport(result *pairingproto.LocalAttestKeyResult) *fakeDeviceTransport {
	return &fakeDeviceTransport{results: map[string]any{pairingproto.MethodLocalAttestKey: result}}
}

func TestRunDeviceAttest_SendsKeyIDAndFreshNonce(t *testing.T) {
	transport := attestResultTransport(&pairingproto.LocalAttestKeyResult{Format: "android-keystore"})

	_, err := runAttestWithPhone(t, transport, true)
	require.NoError(t, err)

	require.Len(t, transport.wire, 1)
	assert.Equal(t, pairingproto.MethodLocalAttestKey, transport.requests[0].Method)
	var params pairingproto.LocalAttestKeyParams
	require.NoError(t, json.Unmarshal(transport.wire[0], &params))
	assert.Equal(t, "signing-key", params.KeyID)
	assert.Len(t, params.Nonce, 32, "the challenge nonce is 32 random bytes")
	assert.True(t, transport.closed, "the phone channel is closed on return")
}

func TestRunDeviceAttest_PhoneFailures(t *testing.T) {
	tests := []struct {
		name      string
		transport *fakeDeviceTransport
	}{
		{"connect fails", &fakeDeviceTransport{connectErr: errors.New("link down")}},
		{"send fails", &fakeDeviceTransport{sendErr: errors.New("timeout")}},
		{"phone refuses", &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
			pairingproto.MethodLocalAttestKey: {Code: -32000, Message: "key not found"},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runAttestWithPhone(t, tt.transport, true)
			require.Error(t, err)
			assert.True(t, tt.transport.closed, "the phone channel is closed on failure")
		})
	}
}

func TestRunDeviceAttest_PhoneRefusalCarriesTheRPCError(t *testing.T) {
	transport := &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
		pairingproto.MethodLocalAttestKey: {Code: -32000, Message: "key not found"},
	}}

	_, err := runAttestWithPhone(t, transport, true)
	require.ErrorIs(t, err, ErrDeviceAttestFailed)
	assert.Contains(t, err.Error(), "[-32000] key not found")
}

func TestRunDeviceAttest_EmptyChainWarns(t *testing.T) {
	transport := attestResultTransport(&pairingproto.LocalAttestKeyResult{
		Format:        "android-keystore",
		SecurityLevel: "strongbox",
	})

	out, err := runAttestWithPhone(t, transport, false)
	require.NoError(t, err)
	assert.Contains(t, out, `Attesting key "signing-key" on device "Test Phone"`)
	assert.Contains(t, out, "Security Level:  strongbox")
	assert.Contains(t, out, "Chain Length:    0 certificates")
	assert.Contains(t, out, "Nonce Match:     false", "a reply that does not echo the nonce never matches")
	assert.Contains(t, out, "WARNING: Empty certificate chain returned.")
}

func TestRunDeviceAttest_UnparseableChainWarns(t *testing.T) {
	transport := attestResultTransport(&pairingproto.LocalAttestKeyResult{
		CertificateChain: [][]byte{[]byte("not a certificate")},
	})

	out, err := runAttestWithPhone(t, transport, false)
	require.NoError(t, err)
	assert.Contains(t, out, "WARNING: Failed to parse certificate chain")
	assert.NotContains(t, out, "Chain Status:", "an unparseable chain is never verified")
}

func TestRunDeviceAttest_NoVerifyPrintsTheChain(t *testing.T) {
	transport := attestResultTransport(&pairingproto.LocalAttestKeyResult{
		CertificateChain: [][]byte{generateTestCertDER(t, x509.ECDSA)},
	})

	out, err := runAttestWithPhone(t, transport, true)
	require.NoError(t, err)
	assert.Contains(t, out, "Test Certificate")
	assert.NotContains(t, out, "Chain Status:", "--no-verify skips verification")
}

// TestRunDeviceAttest_UntrustedChainFailsVerification pins the refusal: a
// chain that does not lead to a Google Hardware Attestation root, or to a
// root in the local trust store, is reported as FAILED and returns
// ErrDeviceAttestVerifyFailed.
func TestRunDeviceAttest_UntrustedChainFailsVerification(t *testing.T) {
	transport := attestResultTransport(&pairingproto.LocalAttestKeyResult{
		CertificateChain: [][]byte{generateTestCertDER(t, x509.ECDSA)},
	})

	out, err := runAttestWithPhone(t, transport, false)
	require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
	assert.Contains(t, out, "Chain Status:        FAILED")
	assert.NotContains(t, out, "VERIFIED")
}

// TestRunDeviceAttest_UnreadableStatusListFailsClosed pins ruling 180: a
// configured status list that cannot be read refuses verification before any
// chain verdict is printed.
func TestRunDeviceAttest_UnreadableStatusListFailsClosed(t *testing.T) {
	cfg := xkeyconfig.DefaultConfig()
	cfg.Phone.AttestationStatusFile = filepath.Join(t.TempDir(), "absent.json")
	previous := loadedConfig
	loadedConfig = cfg
	t.Cleanup(func() { loadedConfig = previous })
	transport := attestResultTransport(&pairingproto.LocalAttestKeyResult{
		CertificateChain: [][]byte{generateTestCertDER(t, x509.ECDSA)},
	})

	out, err := runAttestWithPhone(t, transport, false)

	require.ErrorIs(t, err, ErrDeviceAttestVerifyFailed)
	require.ErrorIs(t, err, xkms.ErrAndroidStatusListUnavailable)
	assert.NotContains(t, out, "Chain Status:")
}
