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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/serverregistry"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
)

// ===========================================================================
// Part 4: Additional coverage push for 90%+ target
// ===========================================================================

// ---------------------------------------------------------------------------
// Helper: generate a valid PEM-encoded CSR for agent enrollment tests.
// ---------------------------------------------------------------------------

func fcpGenerateTestCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test-agent",
			Organization: []string{"test-org"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return csrPEM
}

// ---------------------------------------------------------------------------
// AgentService.ApproveEnrollment - success path with valid enrollment request
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_AgentService_ApproveEnrollment_Success(t *testing.T) {
	svc, collector, enrollment, _ := setupAgentServiceWithEnrollment(t)

	// Submit an enrollment request so we have something to approve.
	csrPEM := fcpGenerateTestCSR(t)
	requestID, err := enrollment.SubmitEnrollmentRequest(csrPEM)
	require.NoError(t, err)
	require.NotEmpty(t, requestID)

	// Approve through the GUI service layer.
	err = svc.ApproveEnrollment(requestID)
	require.NoError(t, err)

	// Check that an event was emitted.
	time.Sleep(50 * time.Millisecond)
	assert.True(t, collector.hasEventType("agent:enrollment_approved"))
}

func TestFinalCoveragePush4_AgentService_ApproveEnrollment_Error(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	// Approve a non-existent request ID.
	err := svc.ApproveEnrollment("non-existent-request-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentEnrollmentFailed)
}

// ---------------------------------------------------------------------------
// AgentService.RejectEnrollment - success path with valid enrollment request
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_AgentService_RejectEnrollment_Success(t *testing.T) {
	svc, collector, enrollment, _ := setupAgentServiceWithEnrollment(t)

	// Submit an enrollment request.
	csrPEM := fcpGenerateTestCSR(t)
	requestID, err := enrollment.SubmitEnrollmentRequest(csrPEM)
	require.NoError(t, err)

	// Reject through the GUI service layer.
	err = svc.RejectEnrollment(requestID, "test rejection reason")
	require.NoError(t, err)

	// Check that an event was emitted.
	time.Sleep(50 * time.Millisecond)
	assert.True(t, collector.hasEventType("agent:enrollment_rejected"))
}

func TestFinalCoveragePush4_AgentService_RejectEnrollment_Error(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	// Reject a non-existent request ID.
	err := svc.RejectEnrollment("non-existent-request-id", "reason")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentEnrollmentFailed)
}

// ---------------------------------------------------------------------------
// AgentService.ListPendingEnrollments - success path with entries
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_AgentService_ListPendingEnrollments_WithEntries(t *testing.T) {
	svc, _, enrollment, _ := setupAgentServiceWithEnrollment(t)

	// Submit two enrollment requests.
	csrPEM1 := fcpGenerateTestCSR(t)
	_, err := enrollment.SubmitEnrollmentRequest(csrPEM1)
	require.NoError(t, err)

	csrPEM2 := fcpGenerateTestCSR(t)
	_, err = enrollment.SubmitEnrollmentRequest(csrPEM2)
	require.NoError(t, err)

	// List through the GUI service layer.
	infos, err := svc.ListPendingEnrollments()
	require.NoError(t, err)
	require.Len(t, infos, 2)

	// Verify fields are populated.
	for _, info := range infos {
		assert.NotEmpty(t, info.ID)
		assert.NotEmpty(t, info.Fingerprint)
		assert.NotEmpty(t, info.RequestedAt)
		assert.Equal(t, "pending", info.Status)
	}
}

func TestFinalCoveragePush4_AgentService_ListPendingEnrollments_EmptyAfterApproval(t *testing.T) {
	svc, _, enrollment, _ := setupAgentServiceWithEnrollment(t)

	// Submit and approve all pending to clear them.
	csrPEM := fcpGenerateTestCSR(t)
	reqID, err := enrollment.SubmitEnrollmentRequest(csrPEM)
	require.NoError(t, err)
	_, _, err = enrollment.ApproveEnrollment(reqID)
	require.NoError(t, err)

	// Now list should return empty (no error), since there are no pending.
	infos, err := svc.ListPendingEnrollments()
	require.NoError(t, err)
	assert.Empty(t, infos)
}

// ---------------------------------------------------------------------------
// AgentService.ListAgents - with enrolled agents
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_AgentService_ListAgents_WithEnrolledAgent(t *testing.T) {
	svc, _, enrollment, store := setupAgentServiceWithEnrollment(t)

	// Submit, approve, and verify agent is stored.
	csrPEM := fcpGenerateTestCSR(t)
	reqID, err := enrollment.SubmitEnrollmentRequest(csrPEM)
	require.NoError(t, err)

	_, _, err = enrollment.ApproveEnrollment(reqID)
	require.NoError(t, err)

	// The store should have the agent now.
	agents, err := store.ListAgents()
	require.NoError(t, err)
	require.NotEmpty(t, agents)

	// List through the service - no server running, so no connected agents.
	infos, err := svc.ListAgents()
	require.NoError(t, err)
	require.NotEmpty(t, infos)

	// All agents should be disconnected since server is not running.
	for _, info := range infos {
		assert.False(t, info.Connected)
		assert.NotEmpty(t, info.ID)
		assert.NotEmpty(t, info.EnrolledAt)
	}
}

// ---------------------------------------------------------------------------
// APIExplorer.Execute - HTML base tag injection branches
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_Execute_HTMLWithHead(t *testing.T) {
	// Server returns HTML with <head> tag.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Test</title></head><body>Hello</body></html>"))
	}))
	defer server.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    server.URL + "/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Verify <base> tag was injected after <head>.
	assert.Contains(t, resp.Body, "<base href=")
	assert.Contains(t, resp.Body, "<head>")
}

func TestFinalCoveragePush4_APIExplorer_Execute_HTMLWithoutHead(t *testing.T) {
	// Server returns HTML with <html> but no <head>.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>No head tag here</body></html>"))
	}))
	defer server.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    server.URL + "/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Verify <base> tag was injected inside a new <head>.
	assert.Contains(t, resp.Body, "<head><base href=")
	assert.Contains(t, resp.Body, "</head>")
}

func TestFinalCoveragePush4_APIExplorer_Execute_HTMLNoStructure(t *testing.T) {
	// Server returns HTML with no <html> or <head> tags.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Just plain content with no structure"))
	}))
	defer server.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    server.URL + "/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Verify <base> tag was prepended.
	assert.True(t, len(resp.Body) > 0)
	assert.Contains(t, resp.Body, "<base href=")
	assert.Contains(t, resp.Body, "Just plain content")
}

func TestFinalCoveragePush4_APIExplorer_Execute_NonHTMLNoInjection(t *testing.T) {
	// Server returns JSON - no HTML injection should happen.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"no injection"}`))
	}))
	defer server.Close()

	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    server.URL + "/test",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotContains(t, resp.Body, "<base href=")
	assert.Contains(t, resp.Body, `"no injection"`)
}

// ---------------------------------------------------------------------------
// APIExplorer.ListAvailableTokens - with FIDO2 service tokens
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_ListAvailableTokens_WithFIDO2(t *testing.T) {
	cfg := newTestExplorerConfig()
	ctx := context.Background()

	// Create a FIDO2 service with a token store containing a FIDO2 token.
	fido2Svc := NewFIDO2Service(nil)
	fido2Svc.SetContext(ctx)
	fido2TokenStore := tokenstore.NewMemoryTokenStore()
	fido2Svc.SetTokenStore(fido2TokenStore)

	// Save a FIDO2 token entry.
	err := fido2TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://fido2-server.example.com",
		Token:     "fido2-jwt-token",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceFIDO2,
		Issuer:    "fido2-server.example.com",
		Subject:   "user@fido2.com",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	cfg.FIDO2Service = fido2Svc

	svc := newTestExplorerService(t, cfg)

	tokens := svc.ListAvailableTokens()
	require.NotEmpty(t, tokens)

	// Find the FIDO2 token.
	found := false
	for _, tok := range tokens {
		if tok.Source == "fido2" && tok.Token == "fido2-jwt-token" {
			found = true
			assert.Contains(t, tok.Label, "FIDO2")
			assert.Contains(t, tok.ID, "fido2:")
			assert.False(t, tok.IsExpired)
			break
		}
	}
	assert.True(t, found, "expected to find FIDO2 token in available tokens")
}

func TestFinalCoveragePush4_APIExplorer_ListAvailableTokens_FIDO2EmptyToken(t *testing.T) {
	cfg := newTestExplorerConfig()
	ctx := context.Background()

	// Create FIDO2 service with empty token store.
	fido2Svc := NewFIDO2Service(nil)
	fido2Svc.SetContext(ctx)
	fido2TokenStore := tokenstore.NewMemoryTokenStore()
	fido2Svc.SetTokenStore(fido2TokenStore)

	cfg.FIDO2Service = fido2Svc
	svc := newTestExplorerService(t, cfg)

	// With no tokens in FIDO2 store, should return empty.
	tokens := svc.ListAvailableTokens()
	assert.Empty(t, tokens)
}

// ---------------------------------------------------------------------------
// APIExplorer.ListAvailableTokens - token store with subject and expiration
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_ListAvailableTokens_WithSubject(t *testing.T) {
	cfg := newTestExplorerConfig()
	ctx := context.Background()

	// Save a token with a subject - should use "source: subject @ server" label.
	err := cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://with-subject.example.com",
		Token:     "jwt-with-subject",
		Source:    tokenstore.SourceFIDO2,
		Subject:   "user@example.com",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)
	tokens := svc.ListAvailableTokens()
	require.Len(t, tokens, 1)
	assert.Contains(t, tokens[0].Label, "user@example.com")
	assert.Contains(t, tokens[0].Label, "with-subject.example.com")
}

func TestFinalCoveragePush4_APIExplorer_ListAvailableTokens_ExpiredToken(t *testing.T) {
	cfg := newTestExplorerConfig()
	ctx := context.Background()

	// Save an expired token.
	err := cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: "https://expired.example.com",
		Token:     "expired-jwt",
		Source:    tokenstore.SourceBootstrap,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // expired
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)
	tokens := svc.ListAvailableTokens()
	require.Len(t, tokens, 1)
	assert.True(t, tokens[0].IsExpired)
	assert.NotEmpty(t, tokens[0].ExpiresAt)
}

// ---------------------------------------------------------------------------
// SealService.ListBlobs - via backend with stored blobs
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_SealService_ListBlobs_ViaBackend(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)
	svc.SetContext(context.Background())

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Store a valid blob.
	blob := sealedBlobStorage{
		ID:        "test-blob-1",
		Label:     "test label",
		SizeBytes: 256,
		CreatedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)
	err = backend.Put(context.Background(), "sealed/test-blob-1.json", data)
	require.NoError(t, err)

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "test-blob-1", entries[0].ID)
	assert.Equal(t, "test label", entries[0].Label)
}

func TestFinalCoveragePush4_SealService_ListBlobs_ViaBackend_InvalidJSON(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)
	svc.SetContext(context.Background())

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Store invalid JSON that should be skipped.
	err := backend.Put(context.Background(), "sealed/bad-blob.json", []byte("not-json"))
	require.NoError(t, err)

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFinalCoveragePush4_SealService_ListBlobs_ViaBackend_Empty(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)
	svc.SetContext(context.Background())

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFinalCoveragePush4_SealService_ListBlobs_ViaBackend_MultipleBlobs(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)
	svc.SetContext(context.Background())

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Store multiple blobs with different timestamps.
	for i, label := range []string{"first", "second", "third"} {
		blob := sealedBlobStorage{
			ID:        label,
			Label:     label,
			SizeBytes: 100 * (i + 1),
			CreatedAt: time.Now().UTC().Add(time.Duration(i) * time.Hour),
		}
		data, err := json.Marshal(blob)
		require.NoError(t, err)
		err = backend.Put(context.Background(), "sealed/"+label+".json", data)
		require.NoError(t, err)
	}

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Should be sorted by creation time, newest first.
	assert.Equal(t, "third", entries[0].ID)
	assert.Equal(t, "second", entries[1].ID)
	assert.Equal(t, "first", entries[2].ID)
}

// ---------------------------------------------------------------------------
// SealService.hashPassword / verifyPassword
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_SealService_HashAndVerifyPassword(t *testing.T) {
	password := "my-secret-password"
	hash, err := hashPassword(password)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, ":")

	// Verify with correct password.
	assert.True(t, verifyPassword(password, hash))

	// Verify with wrong password.
	assert.False(t, verifyPassword("wrong-password", hash))
}

func TestFinalCoveragePush4_SealService_VerifyPassword_InvalidHash(t *testing.T) {
	// No colon separator.
	assert.False(t, verifyPassword("anything", "nocolon"))

	// Invalid hex in salt.
	assert.False(t, verifyPassword("anything", "zzzz:1234"))

	// Invalid hex in hash.
	assert.False(t, verifyPassword("anything", "1234:zzzz"))

	// Empty string.
	assert.False(t, verifyPassword("anything", ""))
}

// ---------------------------------------------------------------------------
// SealService.MigrateFrom - various branches
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_SealService_MigrateFrom_NonExistentSource(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)

	migrated, err := svc.MigrateFrom("/tmp/nonexistent-seal-migration-dir-fcp4")
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestFinalCoveragePush4_SealService_MigrateFrom_EmptySource(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)

	_, err := svc.MigrateFrom("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSealStorageDirNotSet)
}

func TestFinalCoveragePush4_SealService_MigrateFrom_RelativePath(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)

	_, err := svc.MigrateFrom("relative/path")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

func TestFinalCoveragePush4_SealService_MigrateFrom_SameDir(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)

	migrated, err := svc.MigrateFrom(storageDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestFinalCoveragePush4_SealService_MigrateFrom_WithFiles(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	svc := NewSealService(dstDir)

	// Create source blob file.
	blob := sealedBlobStorage{
		ID:    "migrate-test",
		Label: "migration blob",
	}
	data, err := json.Marshal(blob)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(srcDir, "migrate-test.json"), data, 0600)
	require.NoError(t, err)

	// Non-JSON file should be skipped.
	err = os.WriteFile(filepath.Join(srcDir, "readme.txt"), []byte("skip me"), 0600)
	require.NoError(t, err)

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 1, migrated)
}

func TestFinalCoveragePush4_SealService_MigrateFrom_SkipsExisting(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	svc := NewSealService(dstDir)

	blob := sealedBlobStorage{ID: "existing-blob"}
	data, err := json.Marshal(blob)
	require.NoError(t, err)

	// Put the file in both source and destination.
	err = os.WriteFile(filepath.Join(srcDir, "existing-blob.json"), data, 0600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dstDir, "existing-blob.json"), data, 0600)
	require.NoError(t, err)

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated, "should not migrate files that already exist in destination")
}

func TestFinalCoveragePush4_SealService_MigrateFrom_EmptyDir(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	svc := NewSealService(dstDir)

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

// ---------------------------------------------------------------------------
// BarrierService - Seal when barrier is initialized
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_BarrierService_Seal_Success(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)
	assert.False(t, svc.IsUnsealed())
}

func TestFinalCoveragePush4_BarrierService_Seal_WithAuditLogger(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)

	foundSeal := false
	for _, e := range logger.entries {
		if e.Operation == "barrier_sealed" && e.Success {
			foundSeal = true
		}
	}
	assert.True(t, foundSeal)
}

// ---------------------------------------------------------------------------
// BarrierService - GetBackend
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_BarrierService_GetBackend_NilWhenUninitialized(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())

	backend := svc.GetBackend()
	assert.Nil(t, backend)
}

func TestFinalCoveragePush4_BarrierService_GetBackend_AfterInitialize(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	backend := svc.GetBackend()
	assert.NotNil(t, backend)
}

// ---------------------------------------------------------------------------
// BarrierService - storageDir with dataDir set vs fallback
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_BarrierService_StorageDir_WithDataDir(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())

	dataDir := t.TempDir()
	svc.SetDataDir(dataDir)

	assert.Equal(t, dataDir, svc.storageDir())
}

func TestFinalCoveragePush4_BarrierService_StorageDir_Fallback(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())

	assert.Contains(t, svc.storageDir(), "barrier")
	assert.Contains(t, svc.storageDir(), configDir)
}

// ---------------------------------------------------------------------------
// BarrierService - checkInitialized probes directories
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_BarrierService_CheckInitialized_EmptyWhenNoKey(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())

	result := svc.checkInitialized()
	assert.Empty(t, result)
}

func TestFinalCoveragePush4_BarrierService_CheckInitialized_FindsKey(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	result := svc.checkInitialized()
	assert.NotEmpty(t, result)
}

// ---------------------------------------------------------------------------
// BarrierService - Unseal and seal lifecycle
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_BarrierService_UnsealSealCycle(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("password", "software")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())

	err = svc.Seal()
	require.NoError(t, err)
	assert.False(t, svc.IsUnsealed())

	err = svc.Unseal("password", "software")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())
}

// ---------------------------------------------------------------------------
// BarrierService - Status
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_BarrierService_Status_NilBarrier(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())

	status := svc.Status()
	require.NotNil(t, status)
	assert.True(t, status.Sealed)
}

func TestFinalCoveragePush4_BarrierService_Status_AfterInitialize(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	status := svc.Status()
	require.NotNil(t, status)
	assert.False(t, status.Sealed)
}

// ---------------------------------------------------------------------------
// APIExplorer.Execute - with JWT token injection
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_Execute_WithTokenInjection(t *testing.T) {
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cfg := newTestExplorerConfig()
	ctx := context.Background()

	err := cfg.TokenStore.Save(ctx, &tokenstore.TokenEntry{
		ServerURL: server.URL,
		Token:     "test-jwt-token",
		TokenType: tokenstore.TypeBearer,
		Source:    tokenstore.SourceBootstrap,
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    server.URL + "/api/keys",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Bearer test-jwt-token", capturedAuth)
}

// ---------------------------------------------------------------------------
// APIExplorer.extractServerURL - additional branches
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_ExtractServerURL_Valid(t *testing.T) {
	result, err := extractServerURL("https://example.com:8443/api/keys")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com:8443", result)
}

func TestFinalCoveragePush4_ExtractServerURL_MixedCase(t *testing.T) {
	result, err := extractServerURL("HTTPS://EXAMPLE.COM/path")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", result)
}

func TestFinalCoveragePush4_ExtractServerURL_NoScheme(t *testing.T) {
	_, err := extractServerURL("example.com/path")
	require.Error(t, err)
}

func TestFinalCoveragePush4_ExtractServerURL_NoHost(t *testing.T) {
	_, err := extractServerURL("https:///path")
	require.Error(t, err)
}

func TestFinalCoveragePush4_ExtractServerURL_Empty(t *testing.T) {
	_, err := extractServerURL("")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// APIExplorer.GetHistory - with corrupted data in store
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_GetHistory_CorruptedEntry(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)
	ctx := context.Background()

	// Put a valid entry.
	validEntry := HistoryEntry{
		ID:        "valid-id",
		Timestamp: time.Now().UTC(),
		Request:   &ExplorerRequest{Method: "GET", URL: "https://example.com"},
		Response:  &ExplorerResponse{StatusCode: 200, Status: "200 OK"},
	}
	validData, err := json.Marshal(validEntry)
	require.NoError(t, err)
	err = cfg.HistoryStore.Put(ctx, "api_explorer_history/valid-id.json", validData)
	require.NoError(t, err)

	// Put corrupted data.
	err = cfg.HistoryStore.Put(ctx, "api_explorer_history/bad-id.json", []byte("not-json"))
	require.NoError(t, err)

	entries, err := svc.GetHistory()
	require.NoError(t, err)
	// Should have only the valid entry; corrupted one is skipped.
	require.Len(t, entries, 1)
	assert.Equal(t, "valid-id", entries[0].ID)
}

// ---------------------------------------------------------------------------
// APIExplorer.ClearHistory - with entries to delete
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_ClearHistory_WithEntries(t *testing.T) {
	cfg := newTestExplorerConfig()
	svc := newTestExplorerService(t, cfg)
	ctx := context.Background()

	// Store history entries directly.
	for i := 0; i < 3; i++ {
		entry := HistoryEntry{
			ID:        "clear-entry-" + string(rune('A'+i)),
			Timestamp: time.Now().UTC(),
			Request:   &ExplorerRequest{Method: "GET", URL: "https://example.com"},
			Response:  &ExplorerResponse{StatusCode: 200},
		}
		data, err := json.Marshal(entry)
		require.NoError(t, err)
		err = cfg.HistoryStore.Put(ctx, "api_explorer_history/"+entry.ID+".json", data)
		require.NoError(t, err)
	}

	entries, err := svc.GetHistory()
	require.NoError(t, err)
	require.Len(t, entries, 3)

	err = svc.ClearHistory()
	require.NoError(t, err)

	entries, err = svc.GetHistory()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// SealService.SetBackend
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_SealService_SetBackend(t *testing.T) {
	storageDir := t.TempDir()
	svc := NewSealService(storageDir)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "custom-prefix/")

	assert.NotNil(t, svc.backend)
	assert.Equal(t, "custom-prefix/", svc.blobPrefix)
}

// ---------------------------------------------------------------------------
// AgentService - StartServer/StopServer lifecycle with events
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_AgentService_StartStop_EventsEmitted(t *testing.T) {
	svc, collector, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.StartServer(":0")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	status := svc.GetServerStatus()
	assert.True(t, status.Running)

	err = svc.StopServer()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	assert.True(t, collector.hasEventType("agent:server_started"))
	assert.True(t, collector.hasEventType("agent:server_stopped"))
}

// ---------------------------------------------------------------------------
// APIExplorer - server registry lookup branch
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_APIExplorer_Execute_WithRegisteredServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	cfg := newTestExplorerConfig()
	ctx := context.Background()

	err := cfg.Registry.Register(ctx, &serverregistry.ServerEntry{
		URL:      server.URL,
		Name:     "test-server",
		Protocol: serverregistry.ProtocolREST,
	})
	require.NoError(t, err)

	svc := newTestExplorerService(t, cfg)

	resp, err := svc.Execute(&ExplorerRequest{
		Method: "GET",
		URL:    server.URL + "/api/health",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Body, "ok")
}

// ---------------------------------------------------------------------------
// AgentService.GetServerStatus - with running server
// ---------------------------------------------------------------------------

func TestFinalCoveragePush4_AgentService_GetServerStatus_Running(t *testing.T) {
	svc, _, _, _ := setupAgentServiceWithEnrollment(t)

	err := svc.StartServer(":0")
	require.NoError(t, err)
	defer svc.StopServer()

	time.Sleep(100 * time.Millisecond)

	status := svc.GetServerStatus()
	assert.True(t, status.Running)
	assert.NotEmpty(t, status.ListenAddress)
	assert.Contains(t, status.EnrollmentMethods, "one_time_code")
	assert.Contains(t, status.EnrollmentMethods, "admin_approval")
}
