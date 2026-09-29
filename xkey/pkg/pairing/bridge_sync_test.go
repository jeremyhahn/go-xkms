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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	xkeysync "github.com/jeremyhahn/go-xkms/xkey/pkg/sync"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// errTestCredentialNotFound is returned by the in-memory sync accessor
// fakes below in place of a store-specific not-found sentinel.
var errTestCredentialNotFound = errors.New("test: not found")

// pemEncodeCertForTest PEM-encodes a certificate for use as sync wire data.
func pemEncodeCertForTest(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// certFingerprintForTest computes the same SHA-256 fingerprint the sync and
// backup packages use internally.
func certFingerprintForTest(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// memoryTrustStore is a minimal in-memory sync.TrustStoreAccessor used to
// exercise the bridge's remote.sync* handlers end to end. It records the
// purpose each certificate was imported under so tests can prove what a
// paired device's certificates are filed as.
type memoryTrustStore struct {
	certs    map[string]*x509.Certificate
	purposes map[string]truststore.CertPurpose
}

func newMemoryTrustStore() *memoryTrustStore {
	return &memoryTrustStore{
		certs:    make(map[string]*x509.Certificate),
		purposes: make(map[string]truststore.CertPurpose),
	}
}

func (m *memoryTrustStore) Certificates() ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(m.certs))
	for _, c := range m.certs {
		out = append(out, c)
	}
	return out, nil
}

func (m *memoryTrustStore) Metadata(string) (*backup.CertMetadataInfo, error) {
	return nil, nil
}

func (m *memoryTrustStore) Contains(fingerprint string) (bool, error) {
	_, ok := m.certs[fingerprint]
	return ok, nil
}

func (m *memoryTrustStore) ImportPEM(pemData []byte, opts *truststore.AddCertificateOptions) (truststore.ImportResult, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return truststore.ImportResult{}, errors.New("test: invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return truststore.ImportResult{}, err
	}
	fp := certFingerprintForTest(cert)
	if _, exists := m.certs[fp]; exists {
		return truststore.ImportResult{Skipped: 1}, nil
	}
	purpose := truststore.ClassifyCertificate(cert)
	if opts != nil && opts.Purpose != "" {
		purpose = opts.Purpose
	}
	m.certs[fp] = cert
	m.purposes[fp] = purpose
	return truststore.ImportResult{Added: 1}, nil
}

// memoryOATHAccessor is a minimal in-memory sync.OATHAccessor.
type memoryOATHAccessor struct {
	creds map[string]*backup.OATHCredentialInfo
}

func newMemoryOATHAccessor() *memoryOATHAccessor {
	return &memoryOATHAccessor{creds: make(map[string]*backup.OATHCredentialInfo)}
}

func (m *memoryOATHAccessor) List() ([]*backup.OATHCredentialInfo, error) {
	out := make([]*backup.OATHCredentialInfo, 0, len(m.creds))
	for _, c := range m.creds {
		out = append(out, c)
	}
	return out, nil
}

func (m *memoryOATHAccessor) Add(cred *backup.OATHCredentialInfo) error {
	m.creds[cred.ID] = cred
	return nil
}

func (m *memoryOATHAccessor) Get(id string) (*backup.OATHCredentialInfo, error) {
	cred, ok := m.creds[id]
	if !ok {
		return nil, errTestCredentialNotFound
	}
	return cred, nil
}

func (m *memoryOATHAccessor) Update(cred *backup.OATHCredentialInfo) error {
	m.creds[cred.ID] = cred
	return nil
}

// memoryPasswordAccessor is a minimal in-memory sync.PasswordAccessor.
type memoryPasswordAccessor struct {
	passwords map[string]*backup.PasswordInfo
}

func newMemoryPasswordAccessor() *memoryPasswordAccessor {
	return &memoryPasswordAccessor{passwords: make(map[string]*backup.PasswordInfo)}
}

func (m *memoryPasswordAccessor) List() ([]*backup.PasswordInfo, error) {
	out := make([]*backup.PasswordInfo, 0, len(m.passwords))
	for _, p := range m.passwords {
		out = append(out, p)
	}
	return out, nil
}

func (m *memoryPasswordAccessor) Add(pw *backup.PasswordInfo) error {
	m.passwords[pw.ID] = pw
	return nil
}

func (m *memoryPasswordAccessor) Get(id string) (*backup.PasswordInfo, error) {
	pw, ok := m.passwords[id]
	if !ok {
		return nil, errTestCredentialNotFound
	}
	return pw, nil
}

func (m *memoryPasswordAccessor) Update(pw *backup.PasswordInfo) error {
	m.passwords[pw.ID] = pw
	return nil
}

// newTestSyncService builds a real sync.Service over the in-memory
// accessors above, for round-trip dispatch tests.
func newTestSyncService(t *testing.T) (*xkeysync.Service, *memoryTrustStore, *memoryOATHAccessor, *memoryPasswordAccessor) {
	t.Helper()
	ts := newMemoryTrustStore()
	oathAcc := newMemoryOATHAccessor()
	pwAcc := newMemoryPasswordAccessor()

	svc, err := xkeysync.NewService(&xkeysync.Config{DeviceName: "test-laptop"},
		xkeysync.WithTrustStore(ts),
		xkeysync.WithOATH(oathAcc),
		xkeysync.WithPasswords(pwAcc),
	)
	require.NoError(t, err)
	return svc, ts, oathAcc, pwAcc
}

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsSyncMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	syncMethods := []string{
		MethodRemoteSyncTrustStore,
		MethodRemoteSyncOATH,
		MethodRemoteSyncPasswords,
		MethodRemoteSyncAll,
		MethodRemoteSyncStatus,
	}

	for _, method := range syncMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for sync method %s", method)
	}
}

func TestBridge_DispatchMap_TotalHandlerCount_WithSync(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// 16 original + 3 sharing + 3 backup + 2 OATH + 3 PIV + 5 sync
	// + 1 enrollment-certificate store = 33 total handlers.
	assert.Len(t, b.handlers, 33)
}

// --- handleSyncTrustStore tests ---

// TestBridge_HandleSyncTrustStore_NotConfigured verifies that without a
// sync.Service wired into the Bridge, remote.syncTrustStore reports the
// feature as unavailable rather than silently skipping every certificate.
func TestBridge_HandleSyncTrustStore_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{
			{PEM: "cert1", Fingerprint: "fp1"},
			{PEM: "cert2", Fingerprint: "fp2"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// TestBridge_HandleSyncTrustStore_Success verifies the real round trip
// through the dispatch path: a certificate the phone sends is added to the
// laptop's trust store (union merge, dedup by fingerprint), and the
// laptop's own certificates are returned for the phone to merge.
func TestBridge_HandleSyncTrustStore_Success(t *testing.T) {
	svc, ts, _, _ := newTestSyncService(t)
	existing := newTestPIVCertificate(t, "existing-local-cert")
	ts.certs[certFingerprintForTest(existing)] = existing

	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc})
	require.NoError(t, err)

	newCert := newTestPIVCertificate(t, "phone-cert")
	req := newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{
			{PEM: pemEncodeCertForTest(newCert), Fingerprint: certFingerprintForTest(newCert)},
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncTrustStoreResult](t, resp)
	assert.Equal(t, 1, result.Added)
	assert.Equal(t, 0, result.Skipped)
	// Local echoes every laptop certificate, including the one just added.
	assert.Len(t, result.Local, 2)

	// Sending the same certificate again is deduplicated.
	resp2 := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{
			{PEM: pemEncodeCertForTest(newCert), Fingerprint: certFingerprintForTest(newCert)},
		},
	}))
	result2 := decodeResult[RemoteSyncTrustStoreResult](t, resp2)
	assert.Equal(t, 0, result2.Added)
	assert.Equal(t, 1, result2.Skipped)
}

// newForgedGoogleAttestationRoot mints the #1304 attack certificate: a
// self-signed CA whose DN claims to be a Google hardware attestation root.
func newForgedGoogleAttestationRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1304),
		Subject: pkix.Name{
			CommonName:   "Google Hardware Attestation Root",
			Organization: []string{"Google LLC"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// TestBridge_HandleSyncTrustStore_ForgedAnchorIsQuarantined is the #1304
// attack through the phone-facing method: a paired phone pushes a
// self-signed "Google ... Attestation" CA over remote.syncTrustStore. The
// laptop records it under the synced quarantine, never as an Android
// hardware anchor or a user CA.
func TestBridge_HandleSyncTrustStore_ForgedAnchorIsQuarantined(t *testing.T) {
	svc, ts, _, _ := newTestSyncService(t)
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{Logger: testLogger(), SyncService: svc})
	require.NoError(t, err)

	forged := newForgedGoogleAttestationRoot(t)
	fp := certFingerprintForTest(forged)
	resp := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{{PEM: pemEncodeCertForTest(forged), Fingerprint: fp}},
	}))

	result := decodeResult[RemoteSyncTrustStoreResult](t, resp)
	require.Equal(t, 1, result.Added)
	assert.Equal(t, truststore.PurposeSynced, ts.purposes[fp])
}

// TestBridge_HandleSyncTrustStore_AuditsTheWrite verifies a phone's trust
// store write is audited against the device the bridge serves, with what the
// device sent and what the merge did.
func TestBridge_HandleSyncTrustStore_AuditsTheWrite(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	auditLog := &mockAuditLogger{}
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:      testLogger(),
		SyncService: svc,
		AuditLogger: auditLog,
		DeviceID:    "AA:BB:CC:DD:EE:01",
		DeviceName:  "Pixel",
	})
	require.NoError(t, err)

	cert := newTestPIVCertificate(t, "phone-cert")
	resp := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{{PEM: pemEncodeCertForTest(cert), Fingerprint: certFingerprintForTest(cert)}},
	}))
	decodeResult[RemoteSyncTrustStoreResult](t, resp)

	require.Len(t, auditLog.entries, 1)
	entry := auditLog.entries[0]
	assert.Equal(t, audit.OpSyncApplied, entry.Operation)
	assert.Equal(t, "AA:BB:CC:DD:EE:01", entry.DeviceID)
	assert.Equal(t, "Pixel", entry.DeviceName)
	assert.True(t, entry.Success)
	assert.Empty(t, entry.Error)
	assert.Equal(t, xkeysync.DataTypeTrustStore, entry.Details["dataType"])
	assert.Equal(t, 1, entry.Details["received"])
	assert.Equal(t, 1, entry.Details["added"])
	assert.Equal(t, 0, entry.Details["skipped"])
}

// TestBridge_HandleSyncTrustStore_AuditFailureFailsTheCall pins that a sync
// write that cannot be audited is reported as a failed sync, without the
// local audit error text reaching the phone.
func TestBridge_HandleSyncTrustStore_AuditFailureFailsTheCall(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	auditLog := &mockAuditLogger{logErr: errors.New("audit sink unavailable")}
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:      testLogger(),
		SyncService: svc,
		AuditLogger: auditLog,
	})
	require.NoError(t, err)

	cert := newTestPIVCertificate(t, "phone-cert")
	req := newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{{PEM: pemEncodeCertForTest(cert), Fingerprint: certFingerprintForTest(cert)}},
	})
	resp := b.HandleRequest(context.Background(), req)

	assertErrorResponse(t, resp, req.ID, ErrorCodeSyncFailed)
	assert.NotContains(t, resp.Error.Message, "audit sink unavailable")
}

// TestBridge_HandleSyncOATH_AuditsAFailedApply verifies a sync write that
// fails is on record too, as a failure carrying the cause.
func TestBridge_HandleSyncOATH_AuditsAFailedApply(t *testing.T) {
	// A service with no OATH accessor refuses every OATH delta.
	svc, err := xkeysync.NewService(&xkeysync.Config{DeviceName: "test-laptop"},
		xkeysync.WithTrustStore(newMemoryTrustStore()))
	require.NoError(t, err)

	auditLog := &mockAuditLogger{}
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:       testLogger(),
		SyncService:  svc,
		SyncApproval: AlwaysApproveSync,
		AuditLogger:  auditLog,
		DeviceID:     "AA:BB:CC:DD:EE:01",
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncOATH, RemoteSyncOATHParams{
		Credentials: []SyncOATHCredential{{ID: "cred-1", Name: "example"}},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeSyncFailed)

	require.Len(t, auditLog.entries, 1)
	entry := auditLog.entries[0]
	assert.Equal(t, audit.OpSyncApplied, entry.Operation)
	assert.Equal(t, "AA:BB:CC:DD:EE:01", entry.DeviceID)
	assert.False(t, entry.Success)
	assert.Contains(t, entry.Error, xkeysync.ErrOATHSyncFailed.Error())
	assert.Equal(t, xkeysync.DataTypeOATH, entry.Details["dataType"])
}

func TestBridge_HandleSyncTrustStore_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncTrustStore, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleSyncTrustStore_EmptyCertificates(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{
		Certificates: []SyncCertificate{},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncTrustStoreResult](t, resp)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Skipped)
}

// --- handleSyncOATH tests ---

// TestBridge_HandleSyncOATH_NotConfigured verifies that without a
// sync.Service wired into the Bridge, remote.syncOATH reports the feature as
// unavailable rather than silently skipping every credential.
func TestBridge_HandleSyncOATH_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncOATH, RemoteSyncOATHParams{
		Credentials: []SyncOATHCredential{
			{ID: "c1", Name: "GitHub", Secret: "SEC", Type: "totp"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// TestBridge_HandleSyncOATH_Success verifies the real round trip through the
// dispatch path: a new credential is added, and an existing one with a newer
// UpdatedAt replaces the local copy (last-modified-wins).
func TestBridge_HandleSyncOATH_Success(t *testing.T) {
	svc, _, oathAcc, _ := newTestSyncService(t)
	old := &backup.OATHCredentialInfo{ID: "c2", Name: "Slack (old)"}
	require.NoError(t, old.SetSecret("SECOLD"))
	require.NoError(t, oathAcc.Add(old))

	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc, SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncOATH, RemoteSyncOATHParams{
		Credentials: []SyncOATHCredential{
			{ID: "c1", Name: "GitHub", Secret: "SEC", Type: "totp"},
			{ID: "c2", Name: "Slack (new)", Secret: "SEC2", Type: "totp", UpdatedAt: time.Now().UTC().Format(time.RFC3339)},
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncOATHResult](t, resp)
	assert.Equal(t, 1, result.Added)
	assert.Equal(t, 1, result.Updated)
	assert.Equal(t, 0, result.Skipped)

	updated, err := oathAcc.Get("c2")
	require.NoError(t, err)
	assert.Equal(t, "Slack (new)", updated.Name)
}

func TestBridge_HandleSyncOATH_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncOATH, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handleSyncPasswords tests ---

// TestBridge_HandleSyncPasswords_NotConfigured verifies that without a
// sync.Service wired into the Bridge, remote.syncPasswords reports the
// feature as unavailable rather than silently skipping every entry.
func TestBridge_HandleSyncPasswords_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncPasswords, RemoteSyncPasswordsParams{
		Passwords: []SyncPassword{
			{ID: "p1", Name: "GitHub", Password: "pw1"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// TestBridge_HandleSyncPasswords_Success verifies the real round trip
// through the dispatch path: a new password entry is added to the laptop's
// password store.
func TestBridge_HandleSyncPasswords_Success(t *testing.T) {
	svc, _, _, pwAcc := newTestSyncService(t)
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc, SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncPasswords, RemoteSyncPasswordsParams{
		Passwords: []SyncPassword{
			{ID: "p1", Name: "GitHub", Password: "pw1"},
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncPasswordsResult](t, resp)
	assert.Equal(t, 1, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 0, result.Skipped)

	stored, err := pwAcc.Get("p1")
	require.NoError(t, err)
	assert.Equal(t, "pw1", stored.PasswordString())
}

func TestBridge_HandleSyncPasswords_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncPasswords, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handleSyncAll tests ---

// TestBridge_HandleSyncAll_NotConfigured verifies that without a
// sync.Service wired into the Bridge, remote.syncAll reports the feature as
// unavailable rather than an all-empty success.
func TestBridge_HandleSyncAll_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// TestBridge_HandleSyncAll_AllIncluded verifies the real round trip through
// the dispatch path: each requested category reports the laptop's current
// data in Local, with nothing applied since remote.syncAll carries none.
func TestBridge_HandleSyncAll_AllIncluded(t *testing.T) {
	svc, ts, oathAcc, pwAcc := newTestSyncService(t)
	cert := newTestPIVCertificate(t, "laptop-cert")
	ts.certs[certFingerprintForTest(cert)] = cert
	cred := &backup.OATHCredentialInfo{ID: "c1", Name: "GitHub"}
	require.NoError(t, cred.SetSecret("SEC"))
	require.NoError(t, oathAcc.Add(cred))
	pw := &backup.PasswordInfo{ID: "p1", Name: "GitHub"}
	require.NoError(t, pw.SetPassword("pw1"))
	require.NoError(t, pwAcc.Add(pw))

	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc, SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       true,
		IncludePasswords:  true,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncAllResult](t, resp)
	require.NotNil(t, result.TrustStore)
	require.NotNil(t, result.OATH)
	require.NotNil(t, result.Passwords)
	assert.Equal(t, 0, result.TrustStore.Added)
	assert.Equal(t, 0, result.OATH.Added)
	assert.Equal(t, 0, result.Passwords.Added)
	assert.Len(t, result.TrustStore.Local, 1)
	assert.Len(t, result.OATH.Local, 1)
	assert.Len(t, result.Passwords.Local, 1)
}

func TestBridge_HandleSyncAll_TrustStoreOnly(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc, SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: true,
		IncludeOATH:       false,
		IncludePasswords:  false,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncAllResult](t, resp)
	require.NotNil(t, result.TrustStore)
	assert.Nil(t, result.OATH)
	assert.Nil(t, result.Passwords)
}

func TestBridge_HandleSyncAll_NoneIncluded(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), SyncService: svc, SyncApproval: AlwaysApproveSync})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, RemoteSyncAllParams{
		IncludeTrustStore: false,
		IncludeOATH:       false,
		IncludePasswords:  false,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncAllResult](t, resp)
	assert.Nil(t, result.TrustStore)
	assert.Nil(t, result.OATH)
	assert.Nil(t, result.Passwords)
}

func TestBridge_HandleSyncAll_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncAll, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- Sync approval gating tests (go-xkms#1306) ---

// syncGatedMethods are the three remote.sync* methods that export secrets
// (the password vault or OATH credentials) to the phone, and therefore
// require SyncApproval to serve anything at all. remote.syncTrustStore
// (public certificates) and remote.syncStatus (metadata) are deliberately
// excluded: they are exercised elsewhere and must NOT require approval.
var syncGatedMethods = []struct {
	name   string
	method string
	params interface{}
}{
	{"OATH", MethodRemoteSyncOATH, RemoteSyncOATHParams{Credentials: []SyncOATHCredential{{ID: "c1", Name: "GitHub", Secret: "SEC", Type: "totp"}}}},
	{"Passwords", MethodRemoteSyncPasswords, RemoteSyncPasswordsParams{Passwords: []SyncPassword{{ID: "p1", Name: "GitHub", Password: "pw1"}}}},
	{"All", MethodRemoteSyncAll, RemoteSyncAllParams{IncludeTrustStore: true}},
}

// TestBridge_SyncApproval_NilRefusesEveryGatedMethod verifies that a bridge
// with no SyncApproval configured refuses all three secret-exporting sync
// methods, even when a sync.Service is fully wired -- the vault must not be
// exported on the strength of the Noise session alone.
func TestBridge_SyncApproval_NilRefusesEveryGatedMethod(t *testing.T) {
	for _, tc := range syncGatedMethods {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, _ := newTestSyncService(t)
			b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{Logger: testLogger(), SyncService: svc})
			require.NoError(t, err)

			req := newRemoteRequest(tc.method, tc.params)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeSyncApprovalRequired)
		})
	}
}

// TestBridge_SyncApproval_DenialRefusesTheCall verifies that an approver
// which declines the request refuses the call with ErrorCodeSyncNotApproved,
// distinct from "not configured", and that nothing is applied.
func TestBridge_SyncApproval_DenialRefusesTheCall(t *testing.T) {
	for _, tc := range syncGatedMethods {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, _ := newTestSyncService(t)
			denyErr := errors.New("test: operator declined")
			b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
				Logger:      testLogger(),
				SyncService: svc,
				SyncApproval: func(context.Context, *SyncApprovalRequest) error {
					return denyErr
				},
			})
			require.NoError(t, err)

			req := newRemoteRequest(tc.method, tc.params)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeSyncNotApproved)
		})
	}
}

// TestBridge_SyncApproval_ReceivesMethodAndDeviceName verifies the approval
// function is told which method is being asked about and which paired
// device is asking, so a GUI prompt or CLI check can say something useful.
func TestBridge_SyncApproval_ReceivesMethodAndDeviceName(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	var got *SyncApprovalRequest
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{
		Logger:      testLogger(),
		SyncService: svc,
		DeviceName:  "Pixel",
		SyncApproval: func(_ context.Context, req *SyncApprovalRequest) error {
			got = req
			return nil
		},
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncPasswords, RemoteSyncPasswordsParams{
		Passwords: []SyncPassword{{ID: "p1", Name: "GitHub", Password: "pw1"}},
	})
	b.HandleRequest(context.Background(), req)

	require.NotNil(t, got)
	assert.Equal(t, MethodRemoteSyncPasswords, got.Method)
	assert.Equal(t, "Pixel", got.DeviceName)
}

// TestBridge_SyncApproval_TrustStoreAndStatusAreNotGated verifies
// remote.syncTrustStore and remote.syncStatus serve without any
// SyncApproval configured: they are not secret-exporting.
func TestBridge_SyncApproval_TrustStoreAndStatusAreNotGated(t *testing.T) {
	svc, _, _, _ := newTestSyncService(t)
	b, err := NewBridge(&mockTransportClient{}, &BridgeConfig{Logger: testLogger(), SyncService: svc})
	require.NoError(t, err)

	trustResp := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteSyncTrustStore, RemoteSyncTrustStoreParams{}))
	decodeResult[RemoteSyncTrustStoreResult](t, trustResp)

	statusResp := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteSyncStatus, nil))
	decodeResult[RemoteSyncStatusResult](t, statusResp)
}

// --- handleSyncStatus tests ---

func TestBridge_HandleSyncStatus_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		DeviceID: "laptop-test-123",
		Logger:   testLogger(),
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.Equal(t, "laptop-test-123", result.DeviceID)
	assert.Empty(t, result.LastSync)
	assert.NotNil(t, result.StoreChecksums)
	assert.Empty(t, result.StoreChecksums)
}

func TestBridge_HandleSyncStatus_EmptyDeviceID(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.Empty(t, result.DeviceID)
}

// TestBridge_HandleSyncStatus_WithSyncService verifies the real round trip
// through the dispatch path: with a sync.Service configured, remote.syncStatus
// reports live checksums computed over the current store contents.
func TestBridge_HandleSyncStatus_WithSyncService(t *testing.T) {
	svc, ts, _, _ := newTestSyncService(t)
	cert := newTestPIVCertificate(t, "laptop-cert")
	ts.certs[certFingerprintForTest(cert)] = cert

	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{
		DeviceID:    "laptop-test-123",
		Logger:      testLogger(),
		SyncService: svc,
	})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.Equal(t, "laptop-test-123", result.DeviceID)
	require.Contains(t, result.StoreChecksums, "trust_store")
	assert.NotEmpty(t, result.StoreChecksums["trust_store"])
}

// --- Error mapping tests ---

func TestMapErrorToRPC_SyncFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncFailed)
	assert.Equal(t, ErrorCodeSyncFailed, code)
	assert.Contains(t, msg, "sync failed")
}

func TestMapErrorToRPC_SyncConflict(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncConflict)
	assert.Equal(t, ErrorCodeSyncConflict, code)
	assert.Contains(t, msg, "sync conflict")
}

func TestMapErrorToRPC_SyncRemoteUnavailable(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncRemoteUnavailable)
	assert.Equal(t, ErrorCodeSyncRemoteUnavail, code)
	assert.Contains(t, msg, "remote device unavailable")
}

func TestMapErrorToRPC_SyncNoData(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncNoData)
	assert.Equal(t, ErrorCodeSyncNoData, code)
	assert.Contains(t, msg, "no data")
}

func TestMapErrorToRPC_SyncVersionMismatch(t *testing.T) {
	code, msg := mapErrorToRPC(ErrSyncVersionMismatch)
	assert.Equal(t, ErrorCodeSyncVersionMismatch, code)
	assert.Contains(t, msg, "version mismatch")
}

// --- Nil params tests for sync handlers ---

func TestBridge_NilParams_SyncHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// These handlers require params.
	methodsRequiringParams := []string{
		MethodRemoteSyncTrustStore,
		MethodRemoteSyncOATH,
		MethodRemoteSyncPasswords,
		MethodRemoteSyncAll,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
		})
	}
}

func TestBridge_NilParams_SyncStatus_Succeeds(t *testing.T) {
	// SyncStatus does not require params.
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteSyncStatus, nil)
	resp := b.HandleRequest(context.Background(), req)

	require.Nil(t, resp.Error, "expected success but got error: %v", resp.Error)
	result := decodeResult[RemoteSyncStatusResult](t, resp)
	assert.NotNil(t, result.StoreChecksums)
}
