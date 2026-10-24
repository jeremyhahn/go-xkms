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

package pairing

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/truststore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsBackupMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	backupMethods := []string{
		pairingproto.MethodRemoteCreateBackup,
		pairingproto.MethodRemoteRestoreBackup,
		pairingproto.MethodRemoteListBackups,
	}

	for _, method := range backupMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for backup method %s", method)
	}
}

func TestBridge_DispatchMap_TotalHandlerCount_WithBackup(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// 16 original + 3 sharing + 3 backup + 2 OATH + 3 PIV + 5 sync
	// + 1 enrollment-certificate store = 33 total handlers.
	assert.Len(t, b.handlers, 33)
}

// --- handleCreateBackup tests ---

// TestBridge_HandleCreateBackup_NotConfigured verifies that remote.createBackup
// reports the feature as unconfigured (go-xkms#690: backup encryption key
// sourcing and persistence for phone-initiated backups is an open
// architecture question, see bridge_backup.go) rather than fabricating a
// successful, empty backup.
func TestBridge_HandleCreateBackup_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// The requested categories have no configured store on this host.
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
		Label:             "test-backup",
		Password:          testBackupPassword,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleCreateBackup_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandleCreateBackup_NothingRequested(t *testing.T) {
	b := newBackupBridge(t, &mockTransportClient{}, newFakeBackupStores())

	// A password but no category: refused rather than an empty backup.
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		Password: testBackupPassword,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

// --- handleRestoreBackup tests ---

// TestBridge_HandleRestoreBackup_NotConfigured verifies that remote.restoreBackup
// reports the feature as unconfigured rather than discarding the phone's
// backup data while claiming success.
func TestBridge_HandleRestoreBackup_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
		Password:   testBackupPassword,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleRestoreBackup_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandleRestoreBackup_EmptyBackupData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: []byte{},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

func TestBridge_HandleRestoreBackup_NilBackupData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: nil,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
}

// --- handleListBackupsForRestore tests ---

// TestBridge_HandleListBackups_NotConfigured verifies that remote.listBackups
// reports the feature as unconfigured rather than an empty-but-successful
// list, since no persistence/ID convention exists for phone-initiated
// backups yet (see bridge_backup.go).
func TestBridge_HandleListBackups_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(pairingproto.MethodRemoteListBackups, pairingproto.RemoteListBackupsParams{})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeFeatureUnavailable)
}

func TestBridge_HandleListBackups_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// ListBackups does not require params; it still reports unconfigured.
	req := newRemoteRequest(pairingproto.MethodRemoteListBackups, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeFeatureUnavailable)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_BackupFailed(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrBackupFailed)
	assert.Equal(t, pairingproto.ErrorCodeBackupFailed, code)
	assert.Contains(t, msg, "backup creation failed")
}

func TestMapErrorToRPC_BackupRestoreFailed(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrBackupRestoreFailed)
	assert.Equal(t, pairingproto.ErrorCodeBackupRestore, code)
	assert.Contains(t, msg, "backup restore failed")
}

func TestMapErrorToRPC_BackupNotFound(t *testing.T) {
	code, msg := mapErrorToRPC(pairingproto.ErrBackupNotFound)
	assert.Equal(t, pairingproto.ErrorCodeBackupNotFound, code)
	assert.Contains(t, msg, "backup not found")
}

// --- Nil params tests for backup handlers ---

func TestBridge_NilParams_BackupHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// createBackup and restoreBackup require params.
	methodsRequiringParams := []string{
		pairingproto.MethodRemoteCreateBackup,
		pairingproto.MethodRemoteRestoreBackup,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
		})
	}
}

// testBackupPassword seals and opens the backups these tests create.
const testBackupPassword = "correct horse battery staple"

// fakeBackupTrustStore is an in-memory trust store: Certificates serves
// certs, and ImportPEM records every PEM block a restore writes.
type fakeBackupTrustStore struct {
	certs      []*x509.Certificate
	imported   [][]byte
	importOpts []*truststore.AddCertificateOptions

	// purpose is the recorded purpose of every certificate; empty records
	// truststore.PurposeGeneral.
	purpose string
}

func (s *fakeBackupTrustStore) Certificates() ([]*x509.Certificate, error) {
	return s.certs, nil
}

func (s *fakeBackupTrustStore) Metadata(fingerprint string) (*backup.CertMetadataInfo, error) {
	purpose := s.purpose
	if purpose == "" {
		purpose = string(truststore.PurposeGeneral)
	}
	return &backup.CertMetadataInfo{
		Fingerprint: fingerprint,
		Purpose:     purpose,
		Source:      "test",
	}, nil
}

func (s *fakeBackupTrustStore) ImportPEM(pemData []byte, opts *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	s.imported = append(s.imported, pemData)
	s.importOpts = append(s.importOpts, opts)
	return truststore.ImportResult{Added: 1}, nil
}

// fakeBackupOATHStore is an in-memory OATH store keyed by credential ID. List
// returns fresh records on every call, because the backup collector destroys
// the records it reads.
type fakeBackupOATHStore struct {
	secrets map[string][]byte
	lists   int
}

func (s *fakeBackupOATHStore) List() ([]*backup.OATHCredentialInfo, error) {
	s.lists++
	infos := make([]*backup.OATHCredentialInfo, 0, len(s.secrets))
	for id, secret := range s.secrets {
		info := &backup.OATHCredentialInfo{
			ID:        id,
			Name:      id,
			Type:      "totp",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		}
		if err := info.SetSecret(bytes.Clone(secret)); err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *fakeBackupOATHStore) Add(info *backup.OATHCredentialInfo) error {
	secret, err := info.Secret()
	if err != nil {
		return err
	}
	s.secrets[info.ID] = secret
	return nil
}

// fakeBackupPasswordStore is an in-memory static password store keyed by
// entry ID, with the same fresh-records List as fakeBackupOATHStore.
type fakeBackupPasswordStore struct {
	passwords map[string][]byte
	lists     int

	// addErr, when set, is returned by every Add: the store rejects each
	// entry a restore writes.
	addErr error
}

func (s *fakeBackupPasswordStore) List() ([]*backup.PasswordInfo, error) {
	s.lists++
	infos := make([]*backup.PasswordInfo, 0, len(s.passwords))
	for id, password := range s.passwords {
		info := &backup.PasswordInfo{ID: id, Name: id, Username: "alice"}
		if err := info.SetPassword(bytes.Clone(password)); err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *fakeBackupPasswordStore) Add(info *backup.PasswordInfo) error {
	if s.addErr != nil {
		return s.addErr
	}
	password, err := info.Password()
	if err != nil {
		return err
	}
	s.passwords[info.ID] = password
	return nil
}

// fakeBackupStores is one host's set of backup stores.
type fakeBackupStores struct {
	trust     *fakeBackupTrustStore
	oath      *fakeBackupOATHStore
	passwords *fakeBackupPasswordStore
}

// newFakeBackupStores returns empty stores, the target of a restore.
func newFakeBackupStores() *fakeBackupStores {
	return &fakeBackupStores{
		trust:     &fakeBackupTrustStore{},
		oath:      &fakeBackupOATHStore{secrets: map[string][]byte{}},
		passwords: &fakeBackupPasswordStore{passwords: map[string][]byte{}},
	}
}

// seededFakeBackupStores returns stores holding one item per category.
func seededFakeBackupStores(t *testing.T) *fakeBackupStores {
	t.Helper()
	stores := newFakeBackupStores()
	stores.trust.certs = []*x509.Certificate{fakeCertificate(t)}
	stores.oath.secrets["github"] = []byte("JBSWY3DPEHPK3PXP")
	stores.passwords.passwords["router"] = []byte("s3cret-router-password")
	return stores
}

// newBackupBridge returns a bridge whose backup methods use stores, with
// secret export approved.
func newBackupBridge(t *testing.T, client *mockTransportClient, stores *fakeBackupStores) *Bridge {
	t.Helper()
	return newBackupBridgeWithApproval(t, client, stores, AlwaysApproveSync)
}

// newBackupBridgeWithApproval returns a bridge whose backup methods use
// stores and whose secret export is decided by approval.
func newBackupBridgeWithApproval(t *testing.T, client *mockTransportClient, stores *fakeBackupStores, approval SyncApprovalFunc) *Bridge {
	t.Helper()
	b, err := NewBridge(client, &BridgeConfig{
		Logger:           testLogger(),
		SyncApproval:     approval,
		BackupTrustStore: stores.trust,
		BackupOATH:       stores.oath,
		BackupPasswords:  stores.passwords,
	})
	require.NoError(t, err)
	return b
}

// createTestBackup runs remote.createBackup for every local category of
// stores, sealed with testBackupPassword.
func createTestBackup(t *testing.T, stores *fakeBackupStores, label string) pairingproto.RemoteCreateBackupResult {
	t.Helper()
	b := newBackupBridge(t, &mockTransportClient{}, stores)
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
		Label:             label,
		Password:          testBackupPassword,
	})
	return decodeResult[pairingproto.RemoteCreateBackupResult](t, b.HandleRequest(context.Background(), req))
}

func TestBridge_BackupRoundTrip(t *testing.T) {
	source := seededFakeBackupStores(t)
	created := createTestBackup(t, source, "")

	assert.Equal(t, 3, created.ItemCount)
	assert.True(t, strings.HasPrefix(created.BackupID, "backup-"), "unlabeled backup ID %q", created.BackupID)

	var envelope backup.EncryptedBackup
	require.NoError(t, json.Unmarshal(created.BackupData, &envelope))
	require.NotNil(t, envelope.KDF, "a password backup must carry its KDF record")

	target := newFakeBackupStores()
	b := newBackupBridge(t, &mockTransportClient{}, target)
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: created.BackupData,
		Password:   testBackupPassword,
	})
	result := decodeResult[pairingproto.RemoteRestoreBackupResult](t, b.HandleRequest(context.Background(), req))

	assert.True(t, result.Success)
	// The trust store lands in quarantine, so it is pending, not restored.
	assert.ElementsMatch(t, []string{backup.ItemOATH, backup.ItemPasswords}, result.Restored)
	require.Len(t, result.Items, 3)
	for _, item := range result.Items {
		wantRestored, wantQuarantined := 1, 0
		if item.Item == backup.ItemTrustStore {
			wantRestored, wantQuarantined = 0, 1
		}
		assert.Equal(t, wantRestored, item.Restored, item.Item)
		assert.Equal(t, wantQuarantined, item.Quarantined, item.Item)
		assert.Zero(t, item.Skipped, item.Item)
		assert.Empty(t, item.Errors, item.Item)
	}
	assert.Equal(t, source.oath.secrets, target.oath.secrets)
	assert.Equal(t, source.passwords.passwords, target.passwords.passwords)
	require.Len(t, target.trust.imported, 1)
	block, _ := pem.Decode(target.trust.imported[0])
	require.NotNil(t, block)
	assert.Equal(t, source.trust.certs[0].Raw, block.Bytes)
}

func TestBridge_CreateBackup_LabelIsBackupID(t *testing.T) {
	created := createTestBackup(t, seededFakeBackupStores(t), "nightly")
	assert.Equal(t, "nightly", created.BackupID)
}

func TestBridge_RestoreBackup_WrongPassword(t *testing.T) {
	created := createTestBackup(t, seededFakeBackupStores(t), "")

	target := newFakeBackupStores()
	b := newBackupBridge(t, &mockTransportClient{}, target)
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: created.BackupData,
		Password:   "not the backup password",
	})
	resp := b.HandleRequest(context.Background(), req)

	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeBackupRestore)
	assert.Empty(t, target.trust.imported)
	assert.Empty(t, target.oath.secrets)
	assert.Empty(t, target.passwords.passwords)
}

func TestBridge_BackupHandlers_EmptyPassword(t *testing.T) {
	b := newBackupBridge(t, &mockTransportClient{}, seededFakeBackupStores(t))

	tests := []struct {
		name   string
		method string
		params interface{}
		handle func(context.Context, json.RawMessage) (interface{}, error)
	}{
		{
			name:   "create",
			method: pairingproto.MethodRemoteCreateBackup,
			params: pairingproto.RemoteCreateBackupParams{IncludePasswords: true},
			handle: b.handleCreateBackup,
		},
		{
			name:   "restore",
			method: pairingproto.MethodRemoteRestoreBackup,
			params: pairingproto.RemoteRestoreBackupParams{BackupData: []byte("{}")},
			handle: b.handleRestoreBackup,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newRemoteRequest(tt.method, tt.params)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)

			raw, err := json.Marshal(tt.params)
			require.NoError(t, err)
			result, err := tt.handle(context.Background(), raw)
			assert.Nil(t, result)
			assert.ErrorIs(t, err, pairingproto.ErrBackupPasswordRequired)
			assert.ErrorIs(t, err, pairingproto.ErrBridgeInvalidParams)
		})
	}
}

func TestBridge_BackupHandlers_MalformedParams(t *testing.T) {
	b := newBackupBridge(t, &mockTransportClient{}, seededFakeBackupStores(t))

	for _, method := range []string{pairingproto.MethodRemoteCreateBackup, pairingproto.MethodRemoteRestoreBackup} {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, json.RawMessage(`{"password":5}`))
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeInvalidParams)
		})
	}
}

func TestBridge_RestoreBackup_MalformedBackupData(t *testing.T) {
	b := newBackupBridge(t, &mockTransportClient{}, newFakeBackupStores())

	tests := map[string][]byte{
		"not json":      []byte("not a backup envelope"),
		"no KDF record": []byte("{}"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
				BackupData: data,
				Password:   testBackupPassword,
			})
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeBackupRestore)
		})
	}
}

func TestBridge_RestoreBackup_RefusedTrustPurpose(t *testing.T) {
	source := seededFakeBackupStores(t)
	source.trust.purpose = "not-a-purpose"
	created := createTestBackup(t, source, "")

	target := newFakeBackupStores()
	b := newBackupBridge(t, &mockTransportClient{}, target)
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: created.BackupData,
		Password:   testBackupPassword,
	})
	resp := b.HandleRequest(context.Background(), req)

	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeBackupRestore)
	assert.Empty(t, target.trust.imported)
}

func TestBridge_CreateBackup_EmptyStores(t *testing.T) {
	b := newBackupBridge(t, &mockTransportClient{}, newFakeBackupStores())

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeOATH:      true,
		IncludePasswords: true,
		Password:         testBackupPassword,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeBackupFailed)
}

func TestBridge_CreateBackup_IncludeCA(t *testing.T) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeCertificate(t).Raw})
	client := &mockTransportClient{
		caCertResp:   &transport.GetCACertificateResponse{CertificatePEM: certPEM},
		caBundleResp: &transport.GetCABundleResponse{BundlePEM: certPEM},
	}
	b := newBackupBridge(t, client, newFakeBackupStores())

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeCA: true,
		Label:     "ca-only",
		Password:  testBackupPassword,
	})
	created := decodeResult[pairingproto.RemoteCreateBackupResult](t, b.HandleRequest(context.Background(), req))
	assert.Equal(t, "ca-only", created.BackupID)
	assert.Equal(t, 1, created.ItemCount)

	var envelope backup.EncryptedBackup
	require.NoError(t, json.Unmarshal(created.BackupData, &envelope))
	key, err := envelope.PasswordKey([]byte(testBackupPassword))
	require.NoError(t, err)
	defer key.Wipe()
	svc, err := backup.NewService(&backup.Config{DeviceName: "test"})
	require.NoError(t, err)
	archive, err := svc.DecryptBackup(&envelope, key)
	require.NoError(t, err)
	defer archive.Destroy()

	require.NotNil(t, archive.CAData)
	assert.Equal(t, string(certPEM), archive.CAData.CACertPEM)
	assert.Equal(t, string(certPEM), archive.CAData.CAChainPEM)
}

func TestBridge_CreateBackup_IncludeCA_NoChain(t *testing.T) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeCertificate(t).Raw})
	client := &mockTransportClient{
		caCertResp: &transport.GetCACertificateResponse{CertificatePEM: certPEM},
	}
	b := newBackupBridge(t, client, newFakeBackupStores())

	// The CA certificate alone is a complete CA category: a missing chain
	// does not fail the backup.
	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeCA: true,
		Password:  testBackupPassword,
	})
	created := decodeResult[pairingproto.RemoteCreateBackupResult](t, b.HandleRequest(context.Background(), req))
	assert.Equal(t, 1, created.ItemCount)
}

func TestBridge_CreateBackup_CAUnavailable(t *testing.T) {
	b := newBackupBridge(t, &mockTransportClient{}, newFakeBackupStores())

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeCA: true,
		Password:  testBackupPassword,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, req.Generation, pairingproto.ErrorCodeBackupFailed)
}

// errTestExportDeclined is what a test approver refuses secret export with.
var errTestExportDeclined = errors.New("test: operator declined export")

// errTestStoreRejected is what a test store rejects a restored entry with.
var errTestStoreRejected = errors.New("test: store rejected entry")

func TestBridge_CreateBackup_SecretsRequireExportApproval(t *testing.T) {
	refuse := func(context.Context, *SyncApprovalRequest) error { return errTestExportDeclined }

	tests := []struct {
		name     string
		approval SyncApprovalFunc
		params   pairingproto.RemoteCreateBackupParams
		code     int
	}{
		{
			name:   "oath with no approver",
			params: pairingproto.RemoteCreateBackupParams{IncludeOATH: true},
			code:   pairingproto.ErrorCodeSyncApprovalRequired,
		},
		{
			name:   "passwords with no approver",
			params: pairingproto.RemoteCreateBackupParams{IncludePasswords: true},
			code:   pairingproto.ErrorCodeSyncApprovalRequired,
		},
		{
			name:     "oath and trust store refused",
			approval: refuse,
			params:   pairingproto.RemoteCreateBackupParams{IncludeOATH: true, IncludeTrustStore: true},
			code:     pairingproto.ErrorCodeSyncNotApproved,
		},
		{
			name:     "passwords refused",
			approval: refuse,
			params:   pairingproto.RemoteCreateBackupParams{IncludePasswords: true},
			code:     pairingproto.ErrorCodeSyncNotApproved,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stores := seededFakeBackupStores(t)
			b := newBackupBridgeWithApproval(t, &mockTransportClient{}, stores, tt.approval)

			tt.params.Password = testBackupPassword
			req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, tt.params)
			resp := b.HandleRequest(context.Background(), req)

			assertErrorResponse(t, resp, req.ID, req.Generation, tt.code)
			assert.Zero(t, stores.oath.lists, "a refused export must not read the OATH store")
			assert.Zero(t, stores.passwords.lists, "a refused export must not read the password store")
		})
	}
}

func TestBridge_CreateBackup_ApprovedSecretExport(t *testing.T) {
	var approved []string
	approval := func(_ context.Context, req *SyncApprovalRequest) error {
		approved = append(approved, req.Method)
		return nil
	}
	b := newBackupBridgeWithApproval(t, &mockTransportClient{}, seededFakeBackupStores(t), approval)

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeOATH:      true,
		IncludePasswords: true,
		Password:         testBackupPassword,
	})
	created := decodeResult[pairingproto.RemoteCreateBackupResult](t, b.HandleRequest(context.Background(), req))

	assert.Equal(t, 2, created.ItemCount)
	assert.Equal(t, []string{pairingproto.MethodRemoteCreateBackup}, approved, "one approval per backup, naming the method")
}

func TestBridge_CreateBackup_NoSecretsNeedsNoApproval(t *testing.T) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fakeCertificate(t).Raw})
	client := &mockTransportClient{
		caCertResp: &transport.GetCACertificateResponse{CertificatePEM: certPEM},
	}
	// No approver at all: a trust store and CA backup exports no secret.
	b := newBackupBridgeWithApproval(t, client, seededFakeBackupStores(t), nil)

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludeTrustStore: true,
		IncludeCA:         true,
		Password:          testBackupPassword,
	})
	created := decodeResult[pairingproto.RemoteCreateBackupResult](t, b.HandleRequest(context.Background(), req))
	assert.Equal(t, 2, created.ItemCount)
}

func TestBridge_RestoreBackup_RejectedEntryIsReported(t *testing.T) {
	created := createTestBackup(t, seededFakeBackupStores(t), "")

	target := newFakeBackupStores()
	target.passwords.addErr = errTestStoreRejected
	b := newBackupBridge(t, &mockTransportClient{}, target)
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: created.BackupData,
		Password:   testBackupPassword,
	})
	result := decodeResult[pairingproto.RemoteRestoreBackupResult](t, b.HandleRequest(context.Background(), req))

	assert.False(t, result.Success, "a restore with a rejected entry is incomplete")
	assert.ElementsMatch(t, []string{backup.ItemOATH}, result.Restored)
	require.Len(t, result.Items, 3)
	for _, item := range result.Items {
		if item.Item != backup.ItemPasswords {
			assert.Equal(t, 1, item.Restored+item.Quarantined, item.Item)
			assert.Zero(t, item.Skipped, item.Item)
			assert.Empty(t, item.Errors, item.Item)
			continue
		}
		assert.Zero(t, item.Restored)
		assert.Equal(t, 1, item.Skipped)
		require.Len(t, item.Errors, 1)
		assert.Contains(t, item.Errors[0], errTestStoreRejected.Error())
	}
	assert.Empty(t, target.passwords.passwords)
}

// TestBridge_RestoreBackup_QuarantinesTrustStore guards Codex 7030: a phone
// restore files every certificate under the sync quarantine, whatever purpose
// the archive recorded, so a paired phone cannot plant a trust anchor. The
// result reports the certificate as quarantined, not restored.
func TestBridge_RestoreBackup_QuarantinesTrustStore(t *testing.T) {
	source := seededFakeBackupStores(t)
	source.trust.purpose = string(truststore.PurposeAndroidHardware)
	created := createTestBackup(t, source, "")

	target := newFakeBackupStores()
	b := newBackupBridge(t, &mockTransportClient{}, target)
	req := newRemoteRequest(pairingproto.MethodRemoteRestoreBackup, pairingproto.RemoteRestoreBackupParams{
		BackupData: created.BackupData,
		Password:   testBackupPassword,
	})
	result := decodeResult[pairingproto.RemoteRestoreBackupResult](t, b.HandleRequest(context.Background(), req))

	require.Len(t, target.trust.importOpts, 1)
	require.NotNil(t, target.trust.importOpts[0], "nil options would auto-classify the certificate")
	assert.Equal(t, truststore.PurposeSynced, target.trust.importOpts[0].Purpose)
	assert.NotContains(t, result.Restored, backup.ItemTrustStore)
	require.NotEmpty(t, result.Items)
	assert.Equal(t, pairingproto.RemoteRestoreBackupItem{Item: backup.ItemTrustStore, Quarantined: 1}, result.Items[0])
	assert.True(t, result.Success, "a quarantined certificate is pending, not a failure")
}

// TestBridge_CreateBackup_TooLargeForTransport guards Codex 7032: a backup
// that does not fit one TCP frame reaches the phone as
// ErrorCodeMessageTooLarge, through the real router and transport, instead
// of leaving the phone waiting for an answer that never comes.
func TestBridge_CreateBackup_TooLargeForTransport(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, listener.Close()) })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	laptop, err := NewTCPTransport(&TCPTransportConfig{Address: listener.Addr().String()})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, laptop.Close()) })
	require.NoError(t, laptop.Connect(context.Background()))
	var phone net.Conn
	select {
	case phone = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the laptop transport did not connect")
	}
	t.Cleanup(func() { assert.NoError(t, phone.Close()) })
	require.NoError(t, phone.SetDeadline(time.Now().Add(10*time.Second)))

	stores := newFakeBackupStores()
	for i := range 64 {
		stores.passwords.passwords[fmt.Sprintf("entry-%02d", i)] = bytes.Repeat([]byte{'p'}, 1024)
	}
	laptopSession, phoneSession := setupHandshakedNoiseSessions(t)
	router := NewMessageRouter(laptop, laptopSession, newBackupBridge(t, &mockTransportClient{}, stores), testLogger())
	router.Start()
	t.Cleanup(router.Stop)

	req := newRemoteRequest(pairingproto.MethodRemoteCreateBackup, pairingproto.RemoteCreateBackupParams{
		IncludePasswords: true,
		Password:         testBackupPassword,
	})
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)
	ciphertext, err := phoneSession.Encrypt(reqBytes)
	require.NoError(t, err)
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(ciphertext)))
	_, err = phone.Write(append(frame, ciphertext...))
	require.NoError(t, err)

	header := make([]byte, 2)
	_, err = io.ReadFull(phone, header)
	require.NoError(t, err, "the phone must get an answer")
	payload := make([]byte, binary.BigEndian.Uint16(header))
	_, err = io.ReadFull(phone, payload)
	require.NoError(t, err)
	plaintext, err := phoneSession.Decrypt(payload)
	require.NoError(t, err)

	var resp pairingproto.Response
	require.NoError(t, json.Unmarshal(plaintext, &resp))
	assert.Equal(t, req.ID, resp.ID)
	assert.Empty(t, resp.Result)
	require.NotNil(t, resp.Error)
	assert.Equal(t, pairingproto.ErrorCodeMessageTooLarge, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "fewer categories")
}

// --- Whole-node backup operations (go-xkms#728) ---

// --- Custodian group operations ---

// --- Share operations ---

// --- Tenant operations ---

func (m *mockTransportClient) CreateTenant(_ context.Context, _ *transport.CreateTenantRequest) (*transport.CreateTenantResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) GetTenant(_ context.Context, _ string) (*transport.GetTenantResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) ListTenants(_ context.Context) (*transport.ListTenantsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) DeleteTenant(_ context.Context, _ string) error {
	return nil
}

func (m *mockTransportClient) UpdateTenantEntitlements(_ context.Context, _ *transport.UpdateTenantEntitlementsRequest) (*transport.UpdateTenantEntitlementsResponse, error) {
	return nil, nil
}

func (m *mockTransportClient) UpdateTenantQuotas(_ context.Context, _ *transport.UpdateTenantQuotasRequest) (*transport.UpdateTenantQuotasResponse, error) {
	return nil, nil
}

// Init ceremony operations

// Credential management operations

func (m *mockTransportClient) SubmitCredential(_ context.Context, _ *transport.CredentialSubmitRequest) (*transport.CredentialSubmitResponse, error) {
	return nil, errNotImplemented
}

func (m *mockTransportClient) GetCredentialStrategy(_ context.Context) (*transport.CredentialStrategyResponse, error) {
	return nil, errNotImplemented
}

// Algorithm discovery

func (m *mockTransportClient) Algorithms(_ context.Context) (*transport.AlgorithmsResponse, error) {
	return nil, errNotImplemented
}

// Share custody read/delete

// Audit
