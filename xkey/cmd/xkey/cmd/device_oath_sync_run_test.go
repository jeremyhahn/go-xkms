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
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// oathSyncTestCmd builds a fresh cobra.Command carrying the same flags the
// package-level oath phone-sync commands register, so tests never mutate
// the shared global command's flag state.
func oathSyncTestCmd(t *testing.T, storePath string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("device", "", "")
	cmd.Flags().Duration("timeout", 50*time.Millisecond, "")
	cmd.Flags().String("store", "", "")
	if storePath != "" {
		require.NoError(t, setFlagForTest(t, cmd.Flags(), "store", storePath))
	}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	return cmd
}

// brokenNoiseKeyDevice returns a paired device whose LocalNoisePrivateKey is
// not valid base64. unsealDeviceLocalKey (via newPairedDeviceBackendConfig)
// rejects it before any BLE dial is attempted, so this reaches and exercises
// the "connect to phone" failure branch of every phone-sync command without
// touching real Bluetooth hardware.
func brokenNoiseKeyDevice(name string) PairedDevice {
	return PairedDevice{
		Name:                 name,
		Address:              "11:22:33:44:55:66",
		LocalNoisePrivateKey: "not valid base64!!!",
		PairedAt:             time.Now(),
	}
}

func TestRunOATHSync_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := oathSyncTestCmd(t, "")
	err := runOATHSync(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunOATHSync_DeviceNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	cmd := oathSyncTestCmd(t, "")
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "device", "Nonexistent"))
	err := runOATHSync(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestRunOATHSync_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)
	err := runOATHSync(cmd, nil)
	require.ErrorIs(t, err, ErrOATHSyncFailed)
}

func TestRunOATHPush_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := oathSyncTestCmd(t, "")
	err := runOATHPush(cmd, []string{"GitHub"})
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunOATHPush_CredentialNotFound(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)
	err := runOATHPush(cmd, []string{"does-not-exist"})
	require.ErrorIs(t, err, ErrOATHCredentialNotFound)
}

func TestRunOATHPush_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)

	store, err := openOATHStore(cmd, storePath)
	require.NoError(t, err)
	cred := withOATHSecret(&oath.Credential{
		ID: "gh", Name: "GitHub", Type: oath.TypeTOTP, Algorithm: oath.AlgorithmSHA256,
		Digits: 6, Period: 30, CreatedAt: time.Now(),
	}, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.NoError(t, store.Add(cred))
	require.NoError(t, store.Close())

	err = runOATHPush(cmd, []string{"GitHub"})
	require.ErrorIs(t, err, ErrOATHPushFailed)
}

func TestRunOATHPull_NoConfig(t *testing.T) {
	deviceInfoTestHome(t)
	cmd := oathSyncTestCmd(t, "")
	err := runOATHPull(cmd, nil)
	require.ErrorIs(t, err, ErrDeviceNotPaired)
}

func TestRunOATHPull_ConnectFailure(t *testing.T) {
	deviceInfoTestHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{Devices: []PairedDevice{brokenNoiseKeyDevice("A")}}))

	storePath := filepath.Join(t.TempDir(), "oath.json")
	cmd := oathSyncTestCmd(t, storePath)
	err := runOATHPull(cmd, nil)
	require.ErrorIs(t, err, ErrOATHPullFailed)
}

// seedOATHStore writes the named TOTP credentials to a fresh store and returns
// its path.
func seedOATHStore(t *testing.T, names ...string) string {
	t.Helper()

	storePath := filepath.Join(t.TempDir(), "oath.json")
	store, err := oath.NewFileStore(storePath)
	require.NoError(t, err)
	for _, name := range names {
		require.NoError(t, store.Add(withOATHSecret(&oath.Credential{
			ID: name, Name: name, Type: oath.TypeTOTP, Algorithm: oath.AlgorithmSHA256,
			Digits: 6, Period: 30, CreatedAt: time.Now(),
		}, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")))
	}
	require.NoError(t, store.Close())
	return storePath
}

// storedOATHNames lists the credential names in the store at storePath.
func storedOATHNames(t *testing.T, storePath string) []string {
	t.Helper()

	store, err := oath.NewFileStore(storePath)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()

	creds, err := store.List()
	require.NoError(t, err)
	names := make([]string, 0, len(creds))
	for _, cred := range creds {
		names = append(names, cred.Name)
	}
	return names
}

// phoneOATH is a credential as the phone reports it.
func phoneOATH(name string) pairingproto.OATHCredentialInfo {
	return pairingproto.OATHCredentialInfo{
		Name:   name,
		Secret: mustSecretText("GEZDGNBVGY3TQOJQ"),
		Type:   oath.TypeTOTP,
	}
}

// phoneOATHList answers local.oathList with the given credentials.
func phoneOATHList(creds ...pairingproto.OATHCredentialInfo) map[string]any {
	return map[string]any{
		pairingproto.MethodLocalOATHList: &pairingproto.LocalOATHListResult{Credentials: creds},
		pairingproto.MethodLocalOATHAdd:  &pairingproto.LocalOATHAddResult{Success: true, CredentialID: "phone-id-1"},
	}
}

// pushedOATHNames returns the credential names sent with local.oathAdd.
func pushedOATHNames(t *testing.T, transport *fakeDeviceTransport) []string {
	t.Helper()

	var names []string
	for _, req := range transport.requests {
		if req.Method != pairingproto.MethodLocalOATHAdd {
			continue
		}
		params, ok := req.Params.(*pairingproto.LocalOATHAddParams)
		require.True(t, ok, "unexpected params type %T", req.Params)
		names = append(names, params.Credential.Name)
	}
	return names
}

func TestRunOATHSync_MergesBothDirections(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub", "GitLab")

	// The phone already has GitHub (matched case-insensitively) and has AWS,
	// which this device lacks.
	transport := &fakeDeviceTransport{results: phoneOATHList(phoneOATH("github"), phoneOATH("AWS"))}
	useFakeTransport(t, transport)

	cmd := oathSyncTestCmd(t, storePath)
	require.NoError(t, runOATHSync(cmd, nil))

	assert.Equal(t, []string{"GitLab"}, pushedOATHNames(t, transport))
	assert.ElementsMatch(t, []string{"GitHub", "GitLab", "AWS"}, storedOATHNames(t, storePath))

	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	assert.Contains(t, output, "Pushing: GitLab")
	assert.Contains(t, output, "Pulling: AWS")
	assert.Contains(t, output, "Sync complete: 1 pushed, 1 pulled")
	assert.True(t, transport.closed)
}

func TestRunOATHSync_PhoneRefusesAPush(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub")

	transport := &fakeDeviceTransport{
		results:   phoneOATHList(),
		rpcErrors: map[string]*pairingproto.RPCError{pairingproto.MethodLocalOATHAdd: {Code: -32000, Message: "storage full"}},
	}
	useFakeTransport(t, transport)

	cmd := oathSyncTestCmd(t, storePath)
	require.NoError(t, runOATHSync(cmd, nil), "a refused credential is reported, not fatal")

	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	assert.Contains(t, output, "Error: storage full")
	assert.Contains(t, output, "Sync complete: 0 pushed, 0 pulled")
}

// TestRunOATHSync_SkipsAnInvalidPhoneCredential proves a credential the phone
// reports that the local store refuses is reported and skipped, while the
// rest of the phone's credentials are still pulled.
func TestRunOATHSync_SkipsAnInvalidPhoneCredential(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub")

	invalid := phoneOATH("Broken")
	invalid.Type = "bogus"
	transport := &fakeDeviceTransport{results: phoneOATHList(phoneOATH("GitHub"), invalid, phoneOATH("AWS"))}
	useFakeTransport(t, transport)

	cmd := oathSyncTestCmd(t, storePath)
	require.NoError(t, runOATHSync(cmd, nil), "a refused credential is reported, not fatal")

	assert.ElementsMatch(t, []string{"GitHub", "AWS"}, storedOATHNames(t, storePath))
	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	assert.Contains(t, output, "Pulling: Broken\n    Error: "+oath.ErrInvalidType.Error())
	assert.Contains(t, output, "Sync complete: 0 pushed, 1 pulled")
}

func TestRunOATHSync_ListFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub")

	tests := []struct {
		name      string
		transport *fakeDeviceTransport
		detail    string
	}{
		{
			name:      "connect",
			transport: &fakeDeviceTransport{connectErr: errors.New("radio off")},
			detail:    "radio off",
		},
		{
			name:      "send",
			transport: &fakeDeviceTransport{sendErr: errors.New("link dropped")},
			detail:    "link dropped",
		},
		{
			name: "phone error",
			transport: &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
				pairingproto.MethodLocalOATHList: {Code: -32000, Message: "locked"},
			}},
			detail: "[-32000] locked",
		},
		{
			name: "malformed reply",
			transport: &fakeDeviceTransport{results: map[string]any{
				pairingproto.MethodLocalOATHList: "not an object",
			}},
			detail: "failed to decode list result",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			err := runOATHSync(oathSyncTestCmd(t, storePath), nil)
			require.ErrorIs(t, err, ErrOATHSyncFailed)
			assert.ErrorContains(t, err, tt.detail)
			assert.Empty(t, pushedOATHNames(t, tt.transport), "nothing is pushed after a failed list")
		})
	}
}

func TestRunOATHPush_SendsTheCredential(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub")

	transport := &fakeDeviceTransport{results: phoneOATHList()}
	useFakeTransport(t, transport)

	cmd := oathSyncTestCmd(t, storePath)
	require.NoError(t, runOATHPush(cmd, []string{"GitHub"}))

	require.Equal(t, []string{"GitHub"}, pushedOATHNames(t, transport))
	var sent pairingproto.LocalOATHAddParams
	require.NoError(t, json.Unmarshal(transport.wire[0], &sent))
	assert.Equal(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", textOf(sent.Credential.Secret))

	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	assert.Contains(t, output, `Pushing "GitHub" to device "Test Phone"`)
	assert.Contains(t, output, "Credential ID: phone-id-1")
	assert.Contains(t, output, "Credential pushed successfully.")
}

func TestRunOATHPush_PhoneFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub")

	tests := []struct {
		name      string
		transport *fakeDeviceTransport
		detail    string
	}{
		{
			name:      "connect",
			transport: &fakeDeviceTransport{connectErr: errors.New("radio off")},
			detail:    "radio off",
		},
		{
			name:      "send",
			transport: &fakeDeviceTransport{sendErr: errors.New("link dropped")},
			detail:    "link dropped",
		},
		{
			name: "phone error",
			transport: &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
				pairingproto.MethodLocalOATHAdd: {Code: -32000, Message: "duplicate"},
			}},
			detail: "[-32000] duplicate",
		},
		{
			name: "malformed reply",
			transport: &fakeDeviceTransport{results: map[string]any{
				pairingproto.MethodLocalOATHAdd: "not an object",
			}},
			detail: "failed to decode push result",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			cmd := oathSyncTestCmd(t, storePath)
			err := runOATHPush(cmd, []string{"GitHub"})
			require.ErrorIs(t, err, ErrOATHPushFailed)
			assert.ErrorContains(t, err, tt.detail)
			assert.NotContains(t, cmd.OutOrStdout().(*bytes.Buffer).String(), "pushed successfully")
		})
	}
}

func TestRunOATHPull_ImportsOnlyNewCredentials(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "github")

	// "GitHub" maps to the existing ID "github"; "AWS" is new.
	transport := &fakeDeviceTransport{results: phoneOATHList(phoneOATH("GitHub"), phoneOATH("AWS"))}
	useFakeTransport(t, transport)

	cmd := oathSyncTestCmd(t, storePath)
	require.NoError(t, runOATHPull(cmd, nil))

	assert.ElementsMatch(t, []string{"github", "AWS"}, storedOATHNames(t, storePath))
	output := cmd.OutOrStdout().(*bytes.Buffer).String()
	assert.Contains(t, output, "Imported: AWS")
	assert.Contains(t, output, "Pull complete: 1 imported, 1 already present")
	assert.Empty(t, pushedOATHNames(t, transport), "a pull sends nothing")
}

func TestRunOATHPull_EmptyPhone(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t, "GitHub")

	useFakeTransport(t, &fakeDeviceTransport{results: phoneOATHList()})

	cmd := oathSyncTestCmd(t, storePath)
	require.NoError(t, runOATHPull(cmd, nil))

	assert.Contains(t, cmd.OutOrStdout().(*bytes.Buffer).String(), "No credentials found on phone.")
	assert.Equal(t, []string{"GitHub"}, storedOATHNames(t, storePath))
}

func TestRunOATHPull_PhoneFailures(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")
	storePath := seedOATHStore(t)

	tests := []struct {
		name      string
		transport *fakeDeviceTransport
		detail    string
	}{
		{
			name:      "connect",
			transport: &fakeDeviceTransport{connectErr: errors.New("radio off")},
			detail:    "radio off",
		},
		{
			name:      "send",
			transport: &fakeDeviceTransport{sendErr: errors.New("link dropped")},
			detail:    "link dropped",
		},
		{
			name: "phone error",
			transport: &fakeDeviceTransport{rpcErrors: map[string]*pairingproto.RPCError{
				pairingproto.MethodLocalOATHList: {Code: -32000, Message: "locked"},
			}},
			detail: "[-32000] locked",
		},
		{
			name: "malformed reply",
			transport: &fakeDeviceTransport{results: map[string]any{
				pairingproto.MethodLocalOATHList: "not an object",
			}},
			detail: "failed to decode list result",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeTransport(t, tt.transport)

			err := runOATHPull(oathSyncTestCmd(t, storePath), nil)
			require.ErrorIs(t, err, ErrOATHPullFailed)
			assert.ErrorContains(t, err, tt.detail)
			assert.Empty(t, storedOATHNames(t, storePath))
		})
	}
}
