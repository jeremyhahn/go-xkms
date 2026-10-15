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

package cmd

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator"
	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

const fido2TestBarrierPassword = "fido2-barrier-password"

// initFIDO2TestBarrier isolates HOME and initialises a sealed passphrase
// barrier in the xkey data directory, as `xkey barrier init` would.
func initFIDO2TestBarrier(t *testing.T) {
	t.Helper()
	home := isolatedBackupHome(t)
	initTestOATHBarrier(t, home, fido2TestBarrierPassword)
}

func TestCreateFIDO2Storage_BarrierRoundTripsCredential(t *testing.T) {
	initFIDO2TestBarrier(t)

	storage, err := createFIDO2Storage(&FIDO2Config{
		StorageType:     FIDO2StorageTypeBarrier,
		BarrierPassword: fido2TestBarrierPassword,
	}, discardLogger())
	require.NoError(t, err)

	cred := &authenticator.StoredCredential{
		CredentialID: []byte("barrier-cred"),
		RPID:         "example.com",
		Algorithm:    keybackend.COSEAlgES256,
	}
	require.NoError(t, storage.Store(cred))

	loaded, err := storage.Load([]byte("barrier-cred"))
	require.NoError(t, err)
	assert.Equal(t, "example.com", loaded.RPID)
}

func TestCreateBarrierStorage_PasswordFileUsesFirstLine(t *testing.T) {
	initFIDO2TestBarrier(t)
	pwFile := filepath.Join(t.TempDir(), "barrier.pw")
	require.NoError(t, os.WriteFile(pwFile, []byte(fido2TestBarrierPassword+"\nnot-the-password\n"), 0o600))

	storage, err := createBarrierStorage(&FIDO2Config{BarrierPasswordFile: pwFile})
	require.NoError(t, err)
	require.NotNil(t, storage)
}

func TestCreateBarrierStorage_MissingPasswordFile(t *testing.T) {
	initFIDO2TestBarrier(t)

	_, err := createBarrierStorage(&FIDO2Config{
		BarrierPasswordFile: filepath.Join(t.TempDir(), "absent.pw"),
	})
	require.ErrorIs(t, err, ErrFIDO2BarrierPasswordRequired)
}

func TestCreateBarrierStorage_WrongPassword(t *testing.T) {
	initFIDO2TestBarrier(t)

	_, err := createBarrierStorage(&FIDO2Config{BarrierPassword: "wrong-password"})
	require.ErrorIs(t, err, ErrFIDO2BarrierUnsealFailed)
}

func TestCreateFIDO2XKMSSoftwareKeyBackend_MissingPasswordFile(t *testing.T) {
	initFIDO2TestBarrier(t)

	_, err := createFIDO2XKMSSoftwareKeyBackend(&FIDO2Config{
		BarrierPasswordFile: filepath.Join(t.TempDir(), "absent.pw"),
	}, discardLogger())
	require.ErrorIs(t, err, ErrFIDO2BarrierPasswordRequired)
}

func TestCreateFIDO2XKMSSoftwareKeyBackend_WrongPassword(t *testing.T) {
	initFIDO2TestBarrier(t)

	_, err := createFIDO2XKMSSoftwareKeyBackend(&FIDO2Config{BarrierPassword: "wrong-password"}, discardLogger())
	require.ErrorIs(t, err, ErrFIDO2BarrierUnsealFailed)
}

// The software key backend's keys are exportable, so a credential stored
// without an inline private key is still synced to CDP through the backend,
// while a credential the backend never generated is skipped.
func TestSyncCredentialsToCDP_ExportsKeysFromSoftwareBackend(t *testing.T) {
	initFIDO2TestBarrier(t)
	t.Cleanup(xkms.Reset)
	pwFile := filepath.Join(t.TempDir(), "barrier.pw")
	require.NoError(t, os.WriteFile(pwFile, []byte(fido2TestBarrierPassword+"\n"), 0o600))

	backend, err := createFIDO2XKMSSoftwareKeyBackend(&FIDO2Config{BarrierPasswordFile: pwFile}, discardLogger())
	require.NoError(t, err)
	assert.Equal(t, xkms.BackendTypeSoftware, backend.Type())

	generatedID := []byte("backend-generated")
	_, _, err = backend.GenerateCredentialKey(keybackend.COSEAlgES256, generatedID)
	require.NoError(t, err)

	storage := authenticator.NewMemoryStorage()
	for _, id := range [][]byte{generatedID, []byte("never-generated")} {
		require.NoError(t, storage.Store(&authenticator.StoredCredential{
			CredentialID: id,
			RPID:         "example.com",
			Algorithm:    keybackend.COSEAlgES256,
		}))
	}

	d := testCDPDevice(storage)
	d.keyBackend = backend
	rec := &recordingBridge{}
	d.syncCredentialsToCDPVia(context.Background(), rec)

	require.Len(t, rec.creds, 1)
	assert.Equal(t, base64.StdEncoding.EncodeToString(generatedID), rec.creds[0].CredentialID)
	assert.NotEmpty(t, privateKeyText(&rec.creds[0]))
}

func TestSyncCredentialsToCDP_SkipsWithoutKeySource(t *testing.T) {
	storage := authenticator.NewMemoryStorage()
	require.NoError(t, storage.Store(&authenticator.StoredCredential{
		CredentialID: []byte("no-key"),
		RPID:         "example.com",
		Algorithm:    keybackend.COSEAlgES256,
	}))

	rec := &recordingBridge{}
	testCDPDevice(storage).syncCredentialsToCDPVia(context.Background(), rec)
	assert.Empty(t, rec.creds, "a credential with no inline key and no key backend cannot be synced")

	testCDPDevice(nil).syncCredentialsToCDPVia(context.Background(), rec)
	assert.Empty(t, rec.creds, "a device without storage has nothing to sync")
}
