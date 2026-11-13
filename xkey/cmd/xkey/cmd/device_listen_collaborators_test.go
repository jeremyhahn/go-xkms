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

// Tests for go-xkms#690's follow-up: "xkey device listen" must wire real
// OATH, PIV and sync collaborators into the Bridge it builds, not leave them
// nil. buildListenBridgeConfig is connectListenBridge's testable half (no
// xkmsd connection required); these tests prove both that it produces
// non-nil collaborators and that a request through a Bridge built from its
// output reaches the same on-disk store "xkey oath"/"xkey device sync"
// read and write.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// certFingerprintForTest computes the same SHA-256 fingerprint the trust
// store and sync package use to key a certificate, so a synced certificate's
// wire Fingerprint matches what the store itself computes on Contains checks.
func certFingerprintForTest(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "test fixture must be valid PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// isolatedListenHome isolates HOME, XKEY_HOME and the XDG directories so
// buildListenBridgeConfig's store resolution (openOATHStore, openSyncService,
// listenPIVStorageProvider -> resolvePIVStoragePath) never touches the real
// host or a directory a concurrent test is using.
func isolatedListenHome(t *testing.T) string {
	t.Helper()
	// isolatedBackupHome (backup_sources_test.go) sets HOME to a fresh
	// t.TempDir() and resets the root command's cached home resolution; it
	// is the same isolation "xkey oath"/"xkey backup"/"xkey device sync"
	// tests already rely on, reused rather than duplicated here.
	dir := isolatedBackupHome(t)
	t.Setenv("XKEY_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("XDG_DATA_HOME", dir)
	return dir
}

// testListenDevice is the paired phone the listen-bridge tests build a
// bridge for.
var testListenDevice = &PairedDevice{Name: "Pixel", Address: "AA:BB:CC:DD:EE:01"}

// TestBuildListenBridgeConfig_AuditsAgainstThePairedDevice guards #1304's
// audit half: the bridge serving a paired phone carries an audit logger and
// the phone's identity, so every remote.sync* write the phone makes into this
// host's stores is on record against that phone.
func TestBuildListenBridgeConfig_AuditsAgainstThePairedDevice(t *testing.T) {
	isolatedListenHome(t)

	bridgeCfg, collaborators := buildListenBridgeConfig(&cobra.Command{}, newTestLogger(),
		loadXKMSdBridgeConfig(), testListenDevice, nil, nil, pairing.AlwaysApproveSync)
	defer collaborators.Close()

	assert.NotNil(t, bridgeCfg.AuditLogger, "bridge calls from the phone must be audited")
	assert.Equal(t, testListenDevice.Address, bridgeCfg.DeviceID)
	assert.Equal(t, testListenDevice.Name, bridgeCfg.DeviceName)
}

// TestBuildListenBridgeConfig_CollaboratorsAreWired is the regression guard
// for the gap this follow-up closes: a BridgeConfig built for "xkey device
// listen" used to leave OATHStore, PIVStorage and SyncService nil, so a real
// paired phone got FeatureUnavailable for OATH, PIV and sync instead of
// reaching this host's actual data.
func TestBuildListenBridgeConfig_CollaboratorsAreWired(t *testing.T) {
	isolatedListenHome(t)
	cmd := &cobra.Command{}
	xkmsdCfg := loadXKMSdBridgeConfig()

	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, testListenDevice, nil, nil, pairing.AlwaysApproveSync)
	defer collaborators.Close()

	assert.NotNil(t, bridgeCfg.OATHStore, "OATHStore must be wired from openOATHStore")
	assert.NotNil(t, bridgeCfg.PIVStorage, "PIVStorage provider must be wired")
	assert.NotNil(t, bridgeCfg.SyncService, "SyncService must be wired from openSyncService")

	storage, err := bridgeCfg.PIVStorage("software")
	require.NoError(t, err, "the PIV storage provider must build usable storage for the default backend")
	require.NoError(t, storage.Close())
}

// TestBuildListenBridgeConfig_OATHRequestReachesRealStore proves a
// remote.oathAdd request served by a Bridge built from
// buildListenBridgeConfig's output lands in the same on-disk OATH store
// openOATHStore ("xkey oath")'s own commands read and write.
func TestBuildListenBridgeConfig_OATHRequestReachesRealStore(t *testing.T) {
	isolatedListenHome(t)
	cmd := &cobra.Command{}
	xkmsdCfg := loadXKMSdBridgeConfig()

	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, testListenDevice, nil, nil, pairing.AlwaysApproveSync)

	bridge, err := pairing.NewBridge(&baseSDKClient{}, bridgeCfg)
	require.NoError(t, err)

	req := pairingproto.NewRequest(pairingproto.MethodRemoteOATHAdd, pairingproto.RemoteOATHAddParams{
		Credential: pairingproto.OATHCredentialInfo{
			Name:      "GitHub",
			Issuer:    "GitHub",
			Secret:    mustSecretText("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
			Type:      "totp",
			Algorithm: "SHA256",
		},
	})
	resp := bridge.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error, "expected success but got: %v", resp.Error)

	result, err := pairingproto.DecodeResult[pairingproto.RemoteOATHAddResult](resp)
	require.NoError(t, err)
	assert.True(t, result.Success)
	require.NotEmpty(t, result.CredentialID)

	// Close the daemon's collaborators, then reopen the OATH store the exact
	// way "xkey oath" would from a fresh process: the credential must have
	// landed in the real on-disk store, not one only the live bridge could
	// see.
	collaborators.Close()

	reopened, err := openOATHStore(cmd, "")
	require.NoError(t, err)
	defer func() { _ = reopened.Close() }()

	cred, err := reopened.Get(result.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, "GitHub", cred.Name)
	assert.Equal(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", secretText(cred))
}

// listenBridgeCall serves one request through bridge and decodes its result,
// failing the test on an RPC error.
func listenBridgeCall[T any](t *testing.T, bridge *pairing.Bridge, method string, params any) *T {
	t.Helper()
	resp := bridge.HandleRequest(context.Background(), pairingproto.NewRequest(method, params))
	require.Nil(t, resp.Error, "%s failed: %v", method, resp.Error)
	result, err := pairingproto.DecodeResult[T](resp)
	require.NoError(t, err)
	return result
}

// listenOATHAdd adds a TOTP credential through the bridge's live remote.oathAdd
// handler and returns its ID.
func listenOATHAdd(t *testing.T, bridge *pairing.Bridge, name, secret string) string {
	t.Helper()
	result := listenBridgeCall[pairingproto.RemoteOATHAddResult](t, bridge, pairingproto.MethodRemoteOATHAdd,
		pairingproto.RemoteOATHAddParams{Credential: pairingproto.OATHCredentialInfo{
			Name: name, Issuer: name, Secret: mustSecretText(secret), Type: "totp", Algorithm: "SHA1",
		}})
	require.NotEmpty(t, result.CredentialID)
	return result.CredentialID
}

// TestBuildListenBridgeConfig_BackupSharesTheLiveOATHStore guards Codex 7044
// on go-xkms#1693: the backup handlers and the live remote.oath* handlers
// must use one OATH store. A file-backed store reads its file only when it
// opens, so a second instance would back up a stale copy, hide restored
// credentials from remote.oathGenerate, and overwrite them on the next write.
func TestBuildListenBridgeConfig_BackupSharesTheLiveOATHStore(t *testing.T) {
	const backupPassword = "listen-wiring-test-password"
	cmd := &cobra.Command{}
	xkmsdCfg := loadXKMSdBridgeConfig()

	// The source host: a credential added after the bridge opened its stores
	// is in the next backup.
	isolatedListenHome(t)
	srcCfg, srcCollaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, testListenDevice, nil, nil, pairing.AlwaysApproveSync)
	defer srcCollaborators.Close()
	require.NotNil(t, srcCollaborators.syncSources)
	require.NotNil(t, srcCollaborators.syncSources.oath)
	assert.Same(t, srcCollaborators.syncSources.oath.store, srcCfg.OATHStore, "remote.oath* must use the sync sources' store")
	assert.Nil(t, srcCollaborators.oathStore, "the shared store has one owner: the sync sources")
	src, err := pairing.NewBridge(&baseSDKClient{}, srcCfg)
	require.NoError(t, err)
	addedID := listenOATHAdd(t, src, "GitHub", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	created := listenBridgeCall[pairingproto.RemoteCreateBackupResult](t, src, pairingproto.MethodRemoteCreateBackup,
		pairingproto.RemoteCreateBackupParams{IncludeOATH: true, Password: backupPassword})

	// A fresh host: the restored credential is visible to remote.oathGenerate.
	isolatedListenHome(t)
	dstCfg, dstCollaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, testListenDevice, nil, nil, pairing.AlwaysApproveSync)
	dst, err := pairing.NewBridge(&baseSDKClient{}, dstCfg)
	require.NoError(t, err)
	restored := listenBridgeCall[pairingproto.RemoteRestoreBackupResult](t, dst, pairingproto.MethodRemoteRestoreBackup,
		pairingproto.RemoteRestoreBackupParams{BackupData: created.BackupData, Password: backupPassword})
	assert.True(t, restored.Success)
	assert.Contains(t, restored.Restored, string(backup.ItemOATH))
	code := listenBridgeCall[pairingproto.RemoteOATHGenerateResult](t, dst, pairingproto.MethodRemoteOATHGenerate,
		pairingproto.RemoteOATHGenerateParams{CredentialID: addedID})
	assert.NotEmpty(t, code.Code)

	// A write after the restore keeps the restored credential on disk.
	laterID := listenOATHAdd(t, dst, "GitLab", "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK")
	dstCollaborators.Close()

	reopened, err := openOATHStore(cmd, "")
	require.NoError(t, err)
	defer func() { _ = reopened.Close() }()
	for _, id := range []string{addedID, laterID} {
		_, err := reopened.Get(id)
		assert.NoError(t, err, "credential %s is missing from the store on disk", id)
	}
}

// TestBuildListenBridgeConfig_SyncUnavailableOwnsItsOATHStore covers the
// fallback: when the sync service cannot open (here the data directory is
// barrier-encrypted), no backup or sync store is wired, and any OATH store
// the bridge serves is the one the collaborators own and close.
func TestBuildListenBridgeConfig_SyncUnavailableOwnsItsOATHStore(t *testing.T) {
	home := isolatedListenHome(t)
	writeBarrierRootKey(t, backupTestDataDir(home), []byte("sealed"))

	bridgeCfg, collaborators := buildListenBridgeConfig(&cobra.Command{}, newTestLogger(),
		loadXKMSdBridgeConfig(), testListenDevice, nil, nil, pairing.AlwaysApproveSync)
	defer collaborators.Close()

	assert.Nil(t, collaborators.syncSources)
	assert.Nil(t, bridgeCfg.SyncService)
	assert.Nil(t, bridgeCfg.BackupOATH)
	assert.Equal(t, collaborators.oathStore, bridgeCfg.OATHStore)
}

// TestBuildListenBridgeConfig_SyncTrustStoreRequestReachesRealStore proves a
// remote.syncTrustStore request served by a Bridge built from
// buildListenBridgeConfig's output lands in the same on-disk trust store
// "xkey device sync" reads and writes.
func TestBuildListenBridgeConfig_SyncTrustStoreRequestReachesRealStore(t *testing.T) {
	isolatedListenHome(t)
	cmd := &cobra.Command{}
	xkmsdCfg := loadXKMSdBridgeConfig()

	bridgeCfg, collaborators := buildListenBridgeConfig(cmd, newTestLogger(), xkmsdCfg, testListenDevice, nil, nil, pairing.AlwaysApproveSync)

	bridge, err := pairing.NewBridge(&baseSDKClient{}, bridgeCfg)
	require.NoError(t, err)

	certPEM := newTestCertificatePEM(t, "phone-sent-cert")
	req := pairingproto.NewRequest(pairingproto.MethodRemoteSyncTrustStore, pairingproto.RemoteSyncTrustStoreParams{
		Certificates: []pairingproto.SyncCertificate{{
			PEM:         string(certPEM),
			Fingerprint: certFingerprintForTest(t, certPEM),
		}},
	})
	resp := bridge.HandleRequest(context.Background(), req)
	require.Nil(t, resp.Error, "expected success but got: %v", resp.Error)

	result, err := pairingproto.DecodeResult[pairingproto.RemoteSyncTrustStoreResult](resp)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Added)

	collaborators.Close()

	dataDir, err := backupDataDir()
	require.NoError(t, err)
	trustStore, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: filepath.Join(dataDir, trustDataSubdir),
	})
	require.NoError(t, err)
	defer func() { _ = trustStore.Close() }()

	certs, err := trustStore.Certificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "phone-sent-cert", certs[0].Subject.CommonName)

	// The phone's certificate is a self-signed CA, which the operator's own
	// import would file as a user CA and so a TLS anchor. Arriving over sync
	// it is quarantined instead (#1304).
	meta, err := trustStore.Metadata(truststore.Fingerprint(certs[0]))
	require.NoError(t, err)
	assert.Equal(t, truststore.PurposeSynced, meta.Purpose)
	roots, err := trustStore.TLSRoots()
	require.NoError(t, err)
	assert.Empty(t, roots)
}
