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

//go:build ble

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// --- Fake phone transport ---

// fakeDeviceTransport records the requests a command sends and replies with
// canned results, standing in for the BLE Noise channel to a phone.
type fakeDeviceTransport struct {
	requests []*pairing.Request

	// createResult is returned for local.createBackup.
	createResult *pairing.LocalCreateBackupResult

	// restoreResult is returned for local.restoreBackup.
	restoreResult *pairing.LocalRestoreBackupResult

	// connectErr, when set, fails the Connect call.
	connectErr error

	// sendErr, when set, fails every SendRequest call.
	sendErr error

	connected bool
	closed    bool
}

func (f *fakeDeviceTransport) Connect(_ context.Context) error {
	if f.connectErr != nil {
		return f.connectErr
	}
	f.connected = true
	return nil
}

func (f *fakeDeviceTransport) SendRequest(_ context.Context, req *pairing.Request) (*pairing.Response, error) {
	f.requests = append(f.requests, req)

	if f.sendErr != nil {
		return nil, f.sendErr
	}

	var payload any
	switch req.Method {
	case pairing.MethodLocalCreateBackup:
		payload = f.createResult
	case pairing.MethodLocalRestoreBackup:
		payload = f.restoreResult
	default:
		return &pairing.Response{Error: &pairing.RPCError{Code: -32601, Message: "method not found"}}, nil
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &pairing.Response{ID: req.ID, Result: raw}, nil
}

func (f *fakeDeviceTransport) Close() error {
	f.closed = true
	return nil
}

// createParams returns the parameters of the recorded local.createBackup
// request.
func (f *fakeDeviceTransport) createParams(t *testing.T) *pairing.LocalCreateBackupParams {
	t.Helper()

	for _, req := range f.requests {
		if req.Method != pairing.MethodLocalCreateBackup {
			continue
		}
		params, ok := req.Params.(*pairing.LocalCreateBackupParams)
		require.True(t, ok, "unexpected params type %T", req.Params)
		return params
	}

	t.Fatal("no local.createBackup request was sent")
	return nil
}

// useFakeTransport installs the fake transport for the duration of the test.
func useFakeTransport(t *testing.T, transport *fakeDeviceTransport) {
	t.Helper()

	previous := dialPairedDevice
	dialPairedDevice = func(_ *phone.PhoneKeyBackendConfig) (deviceBackupTransport, error) {
		return transport, nil
	}
	t.Cleanup(func() { dialPairedDevice = previous })
}

// pairTestDevice writes a devices.yaml holding one paired device with real
// Noise keys, so the command's key decoding runs for real.
func pairTestDevice(t *testing.T, name string) {
	t.Helper()

	localKey, err := pairing.GenerateStaticKey()
	require.NoError(t, err)
	remoteKey, err := pairing.GenerateStaticKey()
	require.NoError(t, err)

	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                 name,
			Address:              "AA:BB:CC:DD:EE:FF",
			NoisePublicKey:       base64.StdEncoding.EncodeToString(remoteKey.Public),
			LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localKey.Private),
			PairedAt:             time.Now().UTC(),
		}},
		DefaultDevice: name,
	}))
}

// runDeviceCmd executes a device backup command with the given flags and
// returns its output.
func runDeviceCmd(t *testing.T, cmd *cobra.Command, run func(*cobra.Command, []string) error, flags map[string]string) (string, error) {
	t.Helper()

	setBackupFlags(t, cmd, flags)

	var out bytes.Buffer
	cmd.SetOut(&out)
	t.Cleanup(func() { cmd.SetOut(nil) })

	err := run(cmd, nil)

	return out.String(), err
}

// --- to-device ---

func TestBackupToDevice_SendsSealedPayload(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairing.LocalCreateBackupResult{Success: true, BackupID: "backup-1"},
	}
	useFakeTransport(t, transport)

	const password = "device-backup-password"

	output, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": password,
	})
	require.NoError(t, err, output)

	params := transport.createParams(t)
	require.NotEmpty(t, params.BackupData,
		"to-device must send the sealed backup, not an empty payload")
	assert.Contains(t, params.Label, "xkey-backup-")

	// The payload must be a real XKBK envelope.
	var envelope backup.EncryptedBackup
	require.NoError(t, json.Unmarshal(params.BackupData, &envelope))
	assert.Equal(t, backup.BackupMagic, envelope.Magic)
	assert.NotEmpty(t, envelope.Nonce)
	assert.NotEmpty(t, envelope.Ciphertext)

	// ... and it must open with the operator's password and carry the seeded
	// data.
	svc, err := backup.NewService(&backup.Config{DeviceName: "test"})
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(&envelope, deriveKey(password))
	require.NoError(t, err)

	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
	require.Len(t, archive.OATHCreds, 1)
	assert.Equal(t, "UnitTestOATH", archive.OATHCreds[0].Name)
	require.Len(t, archive.Passwords, 1)
	assert.Equal(t, "UnitTestEntry", archive.Passwords[0].Name)

	// The sealed bytes must not leak any plaintext value.
	assert.NotContains(t, string(params.BackupData), "s3cret-value")
	assert.NotContains(t, string(params.BackupData), "JBSWY3DPEHPK3PXP")

	assert.Contains(t, output, "Backup ID:")
	assert.True(t, transport.connected)
	assert.True(t, transport.closed)
}

func TestBackupToDevice_GeneratedKeyOpensPayload(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairing.LocalCreateBackupResult{Success: true, BackupID: "backup-2"},
	}
	useFakeTransport(t, transport)

	output, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{})
	require.NoError(t, err, output)

	keyHex := parseGeneratedBackupKey(t, output)

	var envelope backup.EncryptedBackup
	require.NoError(t, json.Unmarshal(transport.createParams(t).BackupData, &envelope))

	svc, err := backup.NewService(&backup.Config{DeviceName: "test"})
	require.NoError(t, err)

	key, err := resolveDecryptionKey("", keyHex)
	require.NoError(t, err)

	archive, err := svc.DecryptBackup(&envelope, key)
	require.NoError(t, err)
	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
}

func TestBackupToDevice_NoDataRefusedBeforeSending(t *testing.T) {
	// Regression guard: the command used to send BackupData: nil and print a
	// backup ID. An empty data set must now fail before the phone is asked to
	// store anything.
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairing.LocalCreateBackupResult{Success: true, BackupID: "backup-empty"},
	}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupNoData)
	assert.Empty(t, transport.requests, "nothing may be sent when there is no data to back up")
}

func TestBackupToDevice_NotPaired(t *testing.T) {
	isolatedBackupHome(t)

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.Empty(t, transport.requests)
}

func TestBackupToDevice_UnknownDevice(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"device": "Missing Phone",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotFound)
}

func TestBackupToDevice_PhoneRejectsBackup(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairing.LocalCreateBackupResult{Success: false, Message: "storage full"},
	}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupToDeviceFailed)
}

func TestBackupToDevice_ConnectFailure(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{connectErr: errors.New("radio unavailable")}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupToDeviceFailed)
	assert.Empty(t, transport.requests)
}

// --- from-device ---

// sealedDevicePayload seals the stores under home into the wire payload a
// phone would hold.
func sealedDevicePayload(t *testing.T, password string) []byte {
	t.Helper()

	sources, err := resolveBackupSources(backupToDeviceCmd, backupStorePaths{})
	require.NoError(t, err)
	defer sources.Close()

	svc, err := backup.NewService(&backup.Config{DeviceName: "test"}, sources.readerOptions()...)
	require.NoError(t, err)

	encrypted, err := svc.CreateBackup(deriveKey(password))
	require.NoError(t, err)

	payload, err := json.Marshal(encrypted)
	require.NoError(t, err)

	return payload
}

func TestBackupFromDevice_RestoresIntoStores(t *testing.T) {
	const password = "device-backup-password"

	// Seal a payload from a populated home, then restore it into a fresh one.
	sourceHome := isolatedBackupHome(t)
	seedBackupStores(t, sourceHome)
	payload := sealedDevicePayload(t, password)

	targetHome := isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		restoreResult: &pairing.LocalRestoreBackupResult{
			BackupData: payload,
			BackupID:   "backup-1",
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		},
	}
	useFakeTransport(t, transport)

	output, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": password,
	})
	require.NoError(t, err, output)

	dataDir := backupTestDataDir(targetHome)

	trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(dataDir, backupTrustStoreDir),
	})
	require.NoError(t, err)
	defer trustStore.Close()
	certs, err := trustStore.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1, "the restored certificate must land in the trust store")
	assert.Equal(t, "backup-unit-test-ca", certs[0].Subject.CommonName)

	oathStore, err := oath.NewFileStore(filepath.Join(dataDir, backupOATHStoreFile))
	require.NoError(t, err)
	defer oathStore.Close()
	creds, err := oathStore.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "UnitTestOATH", creds[0].Name)

	passwordStore, err := openPasswordStore(filepath.Join(dataDir, backupPasswordStoreDir))
	require.NoError(t, err)
	defer passwordStore.Close()
	passwords, err := passwordStore.List()
	require.NoError(t, err)
	require.Len(t, passwords, 1)
	assert.Equal(t, "s3cret-value", passwords[0].Password)
}

func TestBackupFromDevice_EmptyPayloadRefused(t *testing.T) {
	// Regression guard: the command used to report success for whatever the
	// phone returned, including nothing at all.
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		restoreResult: &pairing.LocalRestoreBackupResult{BackupID: "backup-empty"},
	}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDeviceEmptyPayload)
}

func TestBackupFromDevice_NotAnEnvelope(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		restoreResult: &pairing.LocalRestoreBackupResult{
			BackupData: []byte("not an xkey backup"),
			BackupID:   "backup-junk",
		},
	}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)
}

func TestBackupFromDevice_WrongPasswordWritesNothing(t *testing.T) {
	sourceHome := isolatedBackupHome(t)
	seedBackupStores(t, sourceHome)
	payload := sealedDevicePayload(t, "correct-password")

	targetHome := isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		restoreResult: &pairing.LocalRestoreBackupResult{BackupData: payload, BackupID: "backup-1"},
	}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "wrong-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)

	oathStore, err := oath.NewFileStore(filepath.Join(backupTestDataDir(targetHome), backupOATHStoreFile))
	require.NoError(t, err)
	defer oathStore.Close()
	creds, err := oathStore.List()
	require.NoError(t, err)
	assert.Empty(t, creds, "a failed decryption must not write anything")
}

func TestBackupFromDevice_CredentialRequired(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "",
		"key":      "",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupKeyRequired)
	assert.Empty(t, transport.requests, "the phone must not be contacted without a credential")
}

func TestBackupFromDevice_TransportFailure(t *testing.T) {
	isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{sendErr: errors.New("link dropped")}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupFromDeviceFailed)
}

// --- Pairing and transport edge cases ---

func TestBackupToDevice_InvalidLocalNoiseKey(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                 "Broken Phone",
			Address:              "AA:BB:CC:DD:EE:FF",
			NoisePublicKey:       base64.StdEncoding.EncodeToString([]byte("public")),
			LocalNoisePrivateKey: "not-base64!!",
		}},
		DefaultDevice: "Broken Phone",
	}))

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid local noise key")
	assert.Empty(t, transport.requests)
}

func TestBackupToDevice_InvalidPhoneNoiseKey(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)

	localKey, err := pairing.GenerateStaticKey()
	require.NoError(t, err)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                 "Broken Phone",
			Address:              "AA:BB:CC:DD:EE:FF",
			NoisePublicKey:       "not-base64!!",
			LocalNoisePrivateKey: base64.StdEncoding.EncodeToString(localKey.Private),
		}},
		DefaultDevice: "Broken Phone",
	}))

	useFakeTransport(t, &fakeDeviceTransport{})

	_, err = runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid phone noise key")
}

func TestBackupToDevice_DialFailure(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	previous := dialPairedDevice
	dialPairedDevice = func(_ *phone.PhoneKeyBackendConfig) (deviceBackupTransport, error) {
		return nil, errors.New("no bluetooth adapter")
	}
	t.Cleanup(func() { dialPairedDevice = previous })

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupToDeviceFailed)
}

func TestBackupFromDevice_SkippedEntriesReported(t *testing.T) {
	const password = "device-backup-password"

	// Restoring into the home the backup came from: every entry already
	// exists, so all of them are reported as skipped rather than duplicated.
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	payload := sealedDevicePayload(t, password)
	pairTestDevice(t, "Test Phone")

	useFakeTransport(t, &fakeDeviceTransport{
		restoreResult: &pairing.LocalRestoreBackupResult{BackupData: payload, BackupID: "backup-1"},
	})

	output, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": password,
	})
	require.NoError(t, err, output)
	assert.Contains(t, output, "skipped")

	oathStore, err := oath.NewFileStore(filepath.Join(backupTestDataDir(home), backupOATHStoreFile))
	require.NoError(t, err)
	defer oathStore.Close()
	creds, err := oathStore.List()
	require.NoError(t, err)
	assert.Len(t, creds, 1, "an already-present credential must not be duplicated")
}

func TestBackupFromDevice_RestoreWithHexKey(t *testing.T) {
	const password = "device-backup-password"

	sourceHome := isolatedBackupHome(t)
	seedBackupStores(t, sourceHome)
	payload := sealedDevicePayload(t, password)

	targetHome := isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	useFakeTransport(t, &fakeDeviceTransport{
		restoreResult: &pairing.LocalRestoreBackupResult{BackupData: payload, BackupID: "backup-1"},
	})

	output, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"key": hex.EncodeToString(deriveKey(password)),
	})
	require.NoError(t, err, output)

	passwordStore, err := openPasswordStore(filepath.Join(backupTestDataDir(targetHome), backupPasswordStoreDir))
	require.NoError(t, err)
	defer passwordStore.Close()
	passwords, err := passwordStore.List()
	require.NoError(t, err)
	require.Len(t, passwords, 1)
}

func TestBackupToDevice_UnreadableDevicesConfig(t *testing.T) {
	home := isolatedBackupHome(t)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".xkey"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(home, ".xkey", "devices.yaml"), []byte("devices: [::not-yaml"), 0o600))

	useFakeTransport(t, &fakeDeviceTransport{})

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceConfigLoadFailed)
}

func TestBackupFromDevice_NoPairedDevices(t *testing.T) {
	isolatedBackupHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{}))

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "device-backup-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNotPaired)
	assert.Empty(t, transport.requests)
}
