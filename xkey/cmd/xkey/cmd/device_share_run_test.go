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
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

func deviceShareTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().String("label", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	return cmd
}

func deviceImportTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("backend", "software", "")
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	return cmd
}

func TestRunDeviceShare_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	err := runDeviceShare(deviceShareTestCmd(), []string{"software", "my-key"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceShare_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := deviceShareTestCmd()
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "Nonexistent"))
	err := runDeviceShare(cmd, []string{"software", "my-key"})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

// runShareWithPolicy pairs a device, stores policy (when non-nil) and runs
// "device share" against a fake phone, returning that phone.
func runShareWithPolicy(t *testing.T, policy *pairing.SharingPolicy) (*fakeDeviceTransport, error) {
	t.Helper()
	deviceInfoTestHome(t)
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	if policy != nil {
		store, err := loadSharingPolicyStore()
		require.NoError(t, err)
		require.NoError(t, store.SetPolicy(policy))
	}

	var out bytes.Buffer
	cmd := deviceShareTestCmd()
	cmd.SetOut(&out)
	return transport, runDeviceShare(cmd, []string{"software", "my-key"})
}

// TestRunDeviceShare_RefusedWithoutPolicy pins that a key is never offered to
// a phone unless a sharing policy explicitly allows it.
func TestRunDeviceShare_RefusedWithoutPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy *pairing.SharingPolicy
	}{
		{"no policy", nil},
		{"policy disallows sharing", &pairing.SharingPolicy{Backend: "software", KeyID: "my-key", SharePublic: true}},
		{"device not in allow-list", &pairing.SharingPolicy{
			Backend: "software", KeyID: "my-key", AllowShare: true, SharePublic: true,
			AllowedDevices: []string{"another-device"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, err := runShareWithPolicy(t, tt.policy)
			require.ErrorIs(t, err, ErrSharePolicyDenied)
			assert.Empty(t, transport.requests, "a refused share never reaches the phone")
			assert.False(t, transport.connected)
		})
	}
}

// TestRunDeviceShare_KeyLoadFailsBeforeThePhone pins that an unreadable key
// fails the share before any radio work, rather than sending the phone an
// empty request.
func TestRunDeviceShare_KeyLoadFailsBeforeThePhone(t *testing.T) {
	transport, err := runShareWithPolicy(t, &pairing.SharingPolicy{
		Backend: "software", KeyID: "my-key", AllowShare: true, SharePublic: true,
	})
	require.ErrorIs(t, err, ErrShareKeyLoadFailed)
	assert.Empty(t, transport.requests)
	assert.False(t, transport.connected)
}

func TestRunDeviceImport_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	err := runDeviceImport(deviceImportTestCmd(), []string{"my-key"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunDeviceImport_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := deviceImportTestCmd()
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "Nonexistent"))
	err := runDeviceImport(cmd, []string{"my-key"})
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunDeviceImport_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	err := runDeviceImport(deviceImportTestCmd(), []string{"my-key"})
	require.ErrorIs(t, err, ErrShareConnectFailed)
}

func TestRunDeviceImport_ReportsTheImportedKey(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalImportSharedKey: &pairingproto.LocalImportSharedKeyResult{
			Algorithm:      "AES-256-GCM",
			KeyType:        "symmetric",
			Exportable:     true,
			PublicKeyPEM:   make([]byte, 10),
			CertificatePEM: make([]byte, 20),
			WrappedKey:     make([]byte, 40),
			KeySize:        256,
		},
	}}
	useFakeTransport(t, transport)

	cmd := deviceImportTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, runDeviceImport(cmd, []string{"my-key"}))

	require.Len(t, transport.requests, 1)
	params, ok := transport.requests[0].Params.(*pairingproto.LocalImportSharedKeyParams)
	require.True(t, ok)
	assert.Equal(t, "my-key", params.KeyID)
	assert.True(t, transport.closed)

	output := out.String()
	for _, want := range []string{
		`Importing key "my-key" from device "Test Phone"`,
		"Algorithm:       AES-256-GCM",
		"Exportable:      true",
		"Target Backend:  software",
		"Public Key:      10 bytes (PEM)",
		"Certificate:     20 bytes (PEM)",
		"Wrapped Key:     40 bytes",
		"Key Size:        256 bits",
		"Key imported successfully.",
	} {
		assert.Contains(t, output, want)
	}
}

func TestRunDeviceImport_OmitsAbsentMaterial(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
		pairingproto.MethodLocalImportSharedKey: &pairingproto.LocalImportSharedKeyResult{Algorithm: "Ed25519"},
	}})

	cmd := deviceImportTestCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, runDeviceImport(cmd, []string{"my-key"}))

	assert.NotContains(t, out.String(), "Public Key:")
	assert.NotContains(t, out.String(), "Wrapped Key:")
	assert.Contains(t, out.String(), "Key imported successfully.")
}

func TestRunDeviceImport_PhoneFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	tests := []struct {
		name      string
		transport *fakeDeviceTransport
		sentinel  error
		detail    string
	}{
		{
			name:      "connect",
			transport: &fakeDeviceTransport{connectErr: errors.New("radio off")},
			sentinel:  ErrShareConnectFailed,
			detail:    "radio off",
		},
		{
			name:      "send",
			transport: &fakeDeviceTransport{sendErr: errors.New("link dropped")},
			sentinel:  ErrShareImportFailed,
			detail:    "link dropped",
		},
		{
			name: "phone refuses",
			transport: &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
				pairingproto.MethodLocalImportSharedKey: {Code: -32001, Message: "biometric cancelled"},
			}},
			sentinel: ErrShareImportFailed,
			detail:   "[-32001] biometric cancelled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			err := runDeviceImport(deviceImportTestCmd(), []string{"my-key"})
			require.ErrorIs(t, err, tt.sentinel)
			assert.ErrorContains(t, err, tt.detail)
			assert.True(t, tt.transport.closed)
		})
	}

	t.Run("malformed reply", func(t *testing.T) {
		useFakeTransport(t, &fakeDeviceTransport{results: map[string]any{
			pairingproto.MethodLocalImportSharedKey: "not an object",
		}})

		err := runDeviceImport(deviceImportTestCmd(), []string{"my-key"})
		assert.ErrorContains(t, err, "failed to decode import result")
	})
}

// TestLoadSharedKeyMaterial_NoXKMSdListening exercises the real dial path
// against xkmsd's built-in default unix-socket address, which is a relative
// path that never resolves inside a test's working directory: the connect
// fails immediately, so this never touches a real xkmsd or the filesystem
// outside reading "no such file".
func TestLoadSharedKeyMaterial_NoXKMSdListening(t *testing.T) {
	deviceInfoTestHome(t)

	_, err := loadSharedKeyMaterial("software", "my-key", false, discardLogger())
	require.ErrorIs(t, err, ErrShareKeyLoadFailed)
}
