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

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// --- Fake phone transport ---

// fakeDeviceTransport records the requests a command sends and replies with
// canned results, standing in for the BLE Noise channel to a phone.
type fakeDeviceTransport struct {
	requests []*pairingproto.Request

	// wire holds each request's params as serialised at send time, which is
	// what the phone receives: commands release protected params afterwards.
	wire []json.RawMessage

	// createResult is returned for local.createBackup.
	createResult *pairingproto.LocalCreateBackupResult

	// restoreResult is returned for local.restoreBackup.
	restoreResult *pairingproto.LocalRestoreBackupResult

	// connectErr, when set, fails the Connect call.
	connectErr error

	// sendErr, when set, fails every SendRequest call.
	sendErr error

	// results holds the reply for any other method, keyed by method name.
	results map[string]any

	// rpcErrors makes the phone answer a method with a JSON-RPC error.
	rpcErrors map[string]*pairingproto.RPCError

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

func (f *fakeDeviceTransport) SendRequest(_ context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
	f.requests = append(f.requests, req)

	params, err := json.Marshal(req.Params)
	if err != nil {
		return nil, err
	}
	f.wire = append(f.wire, params)

	if f.sendErr != nil {
		return nil, f.sendErr
	}

	if rpcErr, ok := f.rpcErrors[req.Method]; ok {
		return &pairingproto.Response{ID: req.ID, Error: rpcErr}, nil
	}

	var payload any
	switch req.Method {
	case pairingproto.MethodLocalCreateBackup:
		payload = f.createResult
	case pairingproto.MethodLocalRestoreBackup:
		payload = f.restoreResult
	default:
		result, ok := f.results[req.Method]
		if !ok {
			return &pairingproto.Response{Error: &pairingproto.RPCError{Code: -32601, Message: "method not found"}}, nil
		}
		payload = result
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &pairingproto.Response{ID: req.ID, Result: raw}, nil
}

func (f *fakeDeviceTransport) Close() error {
	f.closed = true
	return nil
}

// createParams returns the parameters of the recorded local.createBackup
// request.
func (f *fakeDeviceTransport) createParams(t *testing.T) *pairingproto.LocalCreateBackupParams {
	t.Helper()

	for _, req := range f.requests {
		if req.Method != pairingproto.MethodLocalCreateBackup {
			continue
		}
		params, ok := req.Params.(*pairingproto.LocalCreateBackupParams)
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
	dialPairedDevice = func(_ *phone.PhoneKeyBackendConfig) (pairedDeviceTransport, error) {
		return transport, nil
	}
	t.Cleanup(func() { dialPairedDevice = previous })
}

// pairTestDevice writes a devices.yaml holding one paired device with real
// Noise keys, so the command's key decoding runs for real.
func pairTestDevice(t *testing.T, name string) {
	t.Helper()

	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                 name,
			Address:              "AA:BB:CC:DD:EE:FF",
			NoisePublicKey:       validNoisePublicKeyForTest(t),
			LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
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

// TestBackupDeviceCmds_PasswordFromStdin pins go-xkms#1202: the device
// commands take the backup password from --password-stdin or the
// environment, like the other backup commands.
func TestBackupDeviceCmds_PasswordFromStdin(t *testing.T) {
	for _, cmd := range []*cobra.Command{backupToDeviceCmd, backupFromDeviceCmd} {
		assert.NotNil(t, cmd.Flags().Lookup("password-stdin"), cmd.Name())
		assert.Nil(t, cmd.Flags().Lookup("password"), cmd.Name())
	}
}

func TestBackupToDevice_SendsSealedPayload(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairingproto.LocalCreateBackupResult{Success: true, BackupID: "backup-1"},
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

	require.NotNil(t, envelope.KDF, "a password-sealed envelope must carry its KDF record")
	key, err := envelope.PasswordKey([]byte(password))
	require.NoError(t, err)
	archive, err := svc.DecryptBackup(&envelope, key)
	require.NoError(t, err)

	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
	require.Len(t, archive.OATHCreds, 1)
	assert.Equal(t, "UnitTestOATH", archive.OATHCreds[0].Name)
	require.Len(t, archive.Passwords, 1)
	assert.Equal(t, "UnitTestEntry", archive.Passwords[0].Name)

	// The sealed bytes must not leak any plaintext value.
	assert.NotContains(t, string(params.BackupData), "s3cret-value")
	assert.NotContains(t, string(params.BackupData), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")

	assert.Contains(t, output, "Backup ID:")
	assert.True(t, transport.connected)
	assert.True(t, transport.closed)
}

func TestBackupToDevice_GeneratedKeyOpensPayload(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairingproto.LocalCreateBackupResult{Success: true, BackupID: "backup-2"},
	}
	useFakeTransport(t, transport)

	output, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{})
	require.NoError(t, err, output)

	keyHex := parseGeneratedBackupKey(t, output)

	var envelope backup.EncryptedBackup
	require.NoError(t, json.Unmarshal(transport.createParams(t).BackupData, &envelope))

	svc, err := backup.NewService(&backup.Config{DeviceName: "test"})
	require.NoError(t, err)

	material, err := hex.DecodeString(keyHex)
	require.NoError(t, err)
	key, err := backup.NewRawKey(material)
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
		createResult: &pairingproto.LocalCreateBackupResult{Success: true, BackupID: "backup-empty"},
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

// TestBackupToDevice_AmbiguousDeviceName pins #1315: two paired records
// sharing a name must refuse `backup to-device` instead of silently sending
// the backup to whichever record happens to be first in the file.
func TestBackupToDevice_AmbiguousDeviceName(t *testing.T) {
	isolatedBackupHome(t)
	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{
			{Name: "Test Phone", Address: "11:22:33:44:55:66"},
			{Name: "Test Phone", Address: "AA:BB:CC:DD:EE:FF"},
		},
	}))

	transport := &fakeDeviceTransport{}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
		"device": "Test Phone",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceNameAmbiguous)
	assert.Empty(t, transport.requests)
}

func TestBackupToDevice_PhoneRejectsBackup(t *testing.T) {
	home := isolatedBackupHome(t)
	seedBackupStores(t, home)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		createResult: &pairingproto.LocalCreateBackupResult{Success: false, Message: "storage full"},
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

// sealedDevicePayload seals the stores under home with key into the wire
// payload a phone would hold.
func sealedDevicePayload(t *testing.T, key *backup.Key) []byte {
	t.Helper()

	sources, err := resolveBackupSources(backupToDeviceCmd, backupStorePaths{}, true)
	require.NoError(t, err)
	defer sources.Close()

	svc, err := backup.NewService(&backup.Config{DeviceName: "test"}, sources.readerOptions()...)
	require.NoError(t, err)

	encrypted, err := svc.CreateBackup(key)
	require.NoError(t, err)

	payload, err := json.Marshal(encrypted)
	require.NoError(t, err)

	return payload
}

// devicePasswordKey derives a fresh password key, as "backup to-device"
// does for an operator-supplied password.
func devicePasswordKey(t *testing.T, password string) *backup.Key {
	t.Helper()
	key, err := backup.NewPasswordKey([]byte(password))
	require.NoError(t, err)
	return key
}

func TestBackupFromDevice_RestoresIntoStores(t *testing.T) {
	const password = "device-backup-password"

	// Seal a payload from a populated home, then restore it into a fresh one.
	sourceHome := isolatedBackupHome(t)
	seedBackupStores(t, sourceHome)
	payload := sealedDevicePayload(t, devicePasswordKey(t, password))

	targetHome := isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		restoreResult: &pairingproto.LocalRestoreBackupResult{
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
		BaseDir: filepath.Join(dataDir, trustDataSubdir),
	})
	require.NoError(t, err)
	defer trustStore.Close()
	certs, err := trustStore.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1, "the restored certificate must land in the trust store")
	assert.Equal(t, "backup-unit-test-ca", certs[0].Subject.CommonName)

	oathStore, err := oath.NewFileStore(filepath.Join(dataDir, oathStoreFilename))
	require.NoError(t, err)
	defer oathStore.Close()
	creds, err := oathStore.List()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "UnitTestOATH", creds[0].Name)

	passwordStore, err := openPasswordStore(filepath.Join(dataDir, passwordStoreFeature))
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
		restoreResult: &pairingproto.LocalRestoreBackupResult{BackupID: "backup-empty"},
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
		restoreResult: &pairingproto.LocalRestoreBackupResult{
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
	payload := sealedDevicePayload(t, devicePasswordKey(t, "correct-password"))

	targetHome := isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	transport := &fakeDeviceTransport{
		restoreResult: &pairingproto.LocalRestoreBackupResult{BackupData: payload, BackupID: "backup-1"},
	}
	useFakeTransport(t, transport)

	_, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": "wrong-password",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupDecryptFailed)

	oathStore, err := oath.NewFileStore(filepath.Join(backupTestDataDir(targetHome), oathStoreFilename))
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

	require.NoError(t, saveDevicesConfig(&DevicesConfig{
		Devices: []PairedDevice{{
			Name:                 "Broken Phone",
			Address:              "AA:BB:CC:DD:EE:FF",
			NoisePublicKey:       "not-base64!!",
			LocalNoisePrivateKey: validLocalNoisePrivateKeyForTest(t),
		}},
		DefaultDevice: "Broken Phone",
	}))

	useFakeTransport(t, &fakeDeviceTransport{})

	_, err := runDeviceCmd(t, backupToDeviceCmd, runBackupToDevice, map[string]string{
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
	dialPairedDevice = func(_ *phone.PhoneKeyBackendConfig) (pairedDeviceTransport, error) {
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
	payload := sealedDevicePayload(t, devicePasswordKey(t, password))
	pairTestDevice(t, "Test Phone")

	useFakeTransport(t, &fakeDeviceTransport{
		restoreResult: &pairingproto.LocalRestoreBackupResult{BackupData: payload, BackupID: "backup-1"},
	})

	output, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"password": password,
	})
	require.NoError(t, err, output)
	assert.Contains(t, output, "skipped")

	oathStore, err := oath.NewFileStore(filepath.Join(backupTestDataDir(home), oathStoreFilename))
	require.NoError(t, err)
	defer oathStore.Close()
	creds, err := oathStore.List()
	require.NoError(t, err)
	assert.Len(t, creds, 1, "an already-present credential must not be duplicated")
}

func TestBackupFromDevice_RestoreWithHexKey(t *testing.T) {
	sourceHome := isolatedBackupHome(t)
	seedBackupStores(t, sourceHome)
	rawKey, err := backup.GenerateKey()
	require.NoError(t, err)
	payload := sealedDevicePayload(t, rawKey)

	targetHome := isolatedBackupHome(t)
	pairTestDevice(t, "Test Phone")

	useFakeTransport(t, &fakeDeviceTransport{
		restoreResult: &pairingproto.LocalRestoreBackupResult{BackupData: payload, BackupID: "backup-1"},
	})

	output, err := runDeviceCmd(t, backupFromDeviceCmd, runBackupFromDevice, map[string]string{
		"key": hex.EncodeToString(rawKey.Bytes()),
	})
	require.NoError(t, err, output)

	passwordStore, err := openPasswordStore(filepath.Join(backupTestDataDir(targetHome), passwordStoreFeature))
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
