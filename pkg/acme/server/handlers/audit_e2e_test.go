//go:build codec_json

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

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditListResponse decodes the admin API's paged audit response. The handler
// writes admin.ListResponse, whose Items is an untyped payload; declaring the
// concrete element type here is what lets the assertions read event fields.
type auditListResponse struct {
	Items   []*audit.AuditEvent `json:"items"`
	Total   int                 `json:"total"`
	Page    int                 `json:"page"`
	PerPage int                 `json:"per_page"`
}

// auditTrail is a live audit trail: the logger the ACME handlers write through
// and the admin router that reads the same file back.
type auditTrail struct {
	logger  audit.AuditLogger
	config  *audit.Config
	router  *mux.Router
	logPath string
}

// newAuditTrail wires a real audit trail rooted at a temporary directory,
// deriving both the logger and the admin query endpoint from one daemon
// configuration exactly as the ACME composition roots do.
func newAuditTrail(t *testing.T, auditCfg config.ACMEAuditConfig) *auditTrail {
	t.Helper()

	dataDir := t.TempDir()
	cfg := auditCfg.AuditConfig(dataDir)

	logger, err := audit.NewFileAuditLogger(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = logger.Close() })

	slogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	var opts []admin.HandlerOption
	if logger.Enabled() {
		querier, err := audit.NewFileQuerier(cfg)
		require.NoError(t, err)
		opts = append(opts, admin.WithAuditQuerier(querier))
	}

	router := mux.NewRouter()
	// The audit route is registered behind the qrdb-backed permission gate. This
	// harness wires an authorizer with no RBAC client, so authorization is
	// disabled and the identity injected below is enough to reach the handler.
	gate := admin.NewPermissionGate(auth.NewAuthorizer(nil), slogger)
	admin.NewHandlers(nil, slogger, opts...).RegisterRoutes(router, nil, gate)

	return &auditTrail{logger: logger, config: cfg, router: router, logPath: cfg.LogPath}
}

// query issues a real GET /admin/audit request through the registered admin
// route and returns the raw response so callers can assert on the status too.
func (a *auditTrail) query(t *testing.T, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()

	require.NoError(t, a.logger.Flush())

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?"+rawQuery, nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		Subject: "audit-test", TenantID: "test-tenant",
	}))
	resp := httptest.NewRecorder()
	a.router.ServeHTTP(resp, req)

	return resp
}

// events queries the trail and decodes the returned page.
func (a *auditTrail) events(t *testing.T, rawQuery string) auditListResponse {
	t.Helper()

	resp := a.query(t, rawQuery)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	var page auditListResponse
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &page))

	return page
}

// expectEvents queries the trail once and requires exactly want matching
// events. The logger writes through a buffered background writer, but query
// flushes first, and Flush is synchronous: it hands the drain to the writer
// goroutine, waits for it, and syncs the file. Every handler records its event
// before it answers, so by the time the response has been read the record is
// durable and one query decides the outcome.
//
// This used to poll under a five-second wall-clock budget. Nothing in that
// loop could turn a wrong answer into a right one; all the budget measured was
// how long one Flush (an fsync) and one file scan take on a contended runner,
// and when the first evaluation outlived it the test failed reporting the
// zero value it never got to replace. A synchronous assertion has no such
// budget to expire.
func (a *auditTrail) expectEvents(t *testing.T, rawQuery string, want int) auditListResponse {
	t.Helper()

	page := a.events(t, rawQuery)
	require.Equal(t, want, page.Total, "expected %d audit events for %q, saw %d", want, rawQuery, page.Total)

	return page
}

// TestAuditTrail_RevocationIsRecordedAndQueryable is the end-to-end proof that
// the audit trail is wired: a certificate is revoked through the real ACME
// handler, and the resulting event is read back through the real
// GET /admin/audit endpoint over the same log file.
func TestAuditTrail_RevocationIsRecordedAndQueryable(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})
	require.True(t, trail.logger.Enabled(), "audit must default to enabled")

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	payload := RevokeCertRequest{
		Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw),
		Reason:      RevocationReasonKeyCompromise,
	}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/revoke-cert", payload, true, account.ID)
	req.Header.Set("X-Request-ID", "revocation-correlation-id")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("User-Agent", "acme-client/1.0")

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	// The revocation itself must have happened; the audit record describes a
	// real state change, not an attempt.
	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	updated, err := certificateDAO.Get(req.Context(), acmeCert.ID)
	require.NoError(t, err)
	require.Equal(t, common.StatusRevoked, updated.Status)

	page := trail.expectEvents(t, "event_type=CERTIFICATE_REVOKED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, audit.EventCertificateRevoked, event.EventType)
	assert.Equal(t, auditAccountRef(account.ID), event.Actor)
	assert.Equal(t, "certificate:"+x509Cert.SerialNumber.String(), event.Resource)
	assert.Equal(t, "revoke", event.Action)
	assert.Equal(t, audit.ResultSuccess, event.Result)
	assert.Equal(t, "revocation-correlation-id", event.RequestID)
	assert.Equal(t, "203.0.113.9", event.SourceIP)
	assert.Equal(t, "acme-client/1.0", event.UserAgent)
	assert.Equal(t, x509Cert.SerialNumber.String(), event.Details["serial_number"])
	assert.EqualValues(t, RevocationReasonKeyCompromise, event.Details["reason_code"])
	assert.False(t, event.Timestamp.IsZero())

	// The trail is on disk, not only in the query response.
	written, err := os.ReadFile(trail.logPath)
	require.NoError(t, err)
	assert.Contains(t, string(written), string(audit.EventCertificateRevoked))
	assert.Contains(t, string(written), x509Cert.SerialNumber.String())
}

// TestAuditTrail_AccountCreationIsRecorded verifies that account registration,
// the other decision an ACME CA must be able to account for, reaches the trail
// with the contact and external-binding context an auditor needs.
func TestAuditTrail_AccountCreationIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	payload := NewAccountRequest{
		Contact:              []string{"mailto:admin@example.com"},
		TermsOfServiceAgreed: true,
	}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/new-account", payload, false, 0)

	resp := httptest.NewRecorder()
	service.NewAccountHandler(resp, req)
	require.Equal(t, http.StatusCreated, resp.Code, "body: %s", resp.Body.String())

	accountID, err := AccountIDFromPublicKey(key.PublicKey)
	require.NoError(t, err)

	page := trail.expectEvents(t, "event_type=ACCOUNT_CREATED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, "system", event.Actor)
	assert.Equal(t, auditAccountRef(accountID), event.Resource)
	assert.Equal(t, "create", event.Action)
	assert.Equal(t, audit.ResultSuccess, event.Result)
	assert.Equal(t, false, event.Details["external_account"])
	assert.Equal(t, []interface{}{"mailto:admin@example.com"}, event.Details["contact"])
}

// TestAuditTrail_IssuanceIsRecordedAndQueryable verifies the control that
// matters most: every certificate the CA signs is recorded with the account
// that asked for it, the order it satisfied, its subject, lifetime, and serial.
func TestAuditTrail_IssuanceIsRecordedAndQueryable(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, mockCA, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)
	mockCA.returnedSerialNum = big.NewInt(4242)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.com"},
		DNSNames: []string{"example.com"},
	}, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	page := trail.expectEvents(t, "event_type=CERTIFICATE_ISSUED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, auditAccountRef(account.ID), event.Actor)
	assert.Equal(t, fmt.Sprintf("order:%d", order.ID), event.Resource)
	assert.Equal(t, "issue", event.Action)
	assert.Equal(t, audit.ResultSuccess, event.Result)
	assert.Equal(t, "4242", event.Details["serial_number"])
	assert.Equal(t, "example.com", event.Details["common_name"])
	assert.NotNil(t, event.Details["validity_days"])
}

// TestAuditTrail_UnauthorizedRevocationIsRecorded verifies that a refused
// operation is audited too: an account that never proved control of a domain
// leaves a failure record even though nothing changed.
func TestAuditTrail_UnauthorizedRevocationIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// No authorization is created for the certificate's domain, so RFC 8555
	// Section 7.6 requires the revocation to be refused.
	acmeCert, x509Cert := createTestCertificateWithSerial(t, service, key)

	payload := RevokeCertRequest{Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw)}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/revoke-cert", payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)

	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	unchanged, err := certificateDAO.Get(req.Context(), acmeCert.ID)
	require.NoError(t, err)
	require.NotEqual(t, common.StatusRevoked, unchanged.Status)

	page := trail.expectEvents(t, "event_type=AUTHORIZATION_FAILED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, auditAccountRef(account.ID), event.Actor)
	assert.Equal(t, "revoke", event.Action)
	assert.Equal(t, audit.ResultFailure, event.Result)
	assert.Equal(t, "test.example.com", event.Details["domain"])
}

// TestAuditTrail_KeyRolloverIsRecorded verifies that account key rollover — a
// change of who can act as an account — is recorded with both key thumbprints,
// so an auditor can follow the identity across the change.
func TestAuditTrail_KeyRolloverIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	oldKey := generateTestKey(t)
	newKey := generateTestKey(t)
	account := createTestAccount(t, service, oldKey)

	req := createKeyChangeRequest(t, service, oldKey, newKey, account.ID)
	resp := httptest.NewRecorder()
	service.KeyChangeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	page := trail.expectEvents(t, "event_type=ACCOUNT_KEY_CHANGED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, auditAccountRef(account.ID), event.Actor)
	assert.Equal(t, auditAccountRef(account.ID), event.Resource)
	assert.Equal(t, "key_rollover", event.Action)
	assert.Equal(t, auditKeyFingerprint(oldKey.PublicKey), event.Details["old_key_fingerprint"])
	assert.Equal(t, auditKeyFingerprint(newKey.PublicKey), event.Details["new_key_fingerprint"])
	assert.NotEqual(t, event.Details["old_key_fingerprint"], event.Details["new_key_fingerprint"])
}

// TestAuditTrail_FiltersAndPaging exercises the query surface the admin API
// exposes over a trail holding more than one page of real events.
func TestAuditTrail_FiltersAndPaging(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	// Three revocations by the same account, so paging has something to split.
	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	serials := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)
		payload := RevokeCertRequest{Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw)}
		req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/revoke-cert", payload, true, account.ID)
		resp := httptest.NewRecorder()
		service.RevokeCertHandler(resp, req)
		require.Equal(t, http.StatusOK, resp.Code)
		serials = append(serials, x509Cert.SerialNumber.String())
	}

	// Filtering by actor returns every event that account caused.
	byActor := trail.expectEvents(t, "actor="+auditAccountRef(account.ID), 3)
	assert.Equal(t, 3, byActor.Total)

	// Paging splits the trail without overlapping or dropping records: each
	// single-event page reports the same total and names a different one of the
	// three revocations, and together the pages account for all of them.
	//
	// The order within the trail is the writer's append order, which the
	// buffered background writer does not guarantee to match request order, so
	// the assertion is on coverage rather than on which serial lands first.
	seen := make(map[string]bool, 3)
	for page := 1; page <= 3; page++ {
		got := trail.events(t, fmt.Sprintf("per_page=1&page=%d", page))
		require.Len(t, got.Items, 1, "page %d", page)
		assert.Equal(t, 3, got.Total, "page %d", page)
		assert.False(t, seen[got.Items[0].Resource], "page %d repeated an event", page)
		seen[got.Items[0].Resource] = true
	}

	for _, serial := range serials {
		assert.True(t, seen["certificate:"+serial], "serial %s missing from the paged trail", serial)
	}

	// A page past the end of the trail is empty rather than an error.
	beyond := trail.events(t, "per_page=1&page=4")
	assert.Empty(t, beyond.Items)
	assert.Equal(t, 3, beyond.Total)

	// A filter that matches nothing reports an empty page, not an error.
	none := trail.events(t, "event_type=CERTIFICATE_ISSUED")
	assert.Equal(t, 0, none.Total)
	assert.Empty(t, none.Items)

	// An impossible time range is rejected rather than silently widened.
	bad := trail.query(t, "start_time=2030-01-01T00:00:00Z&end_time=2020-01-01T00:00:00Z")
	assert.Equal(t, http.StatusBadRequest, bad.Code)
}

// TestAuditTrail_DisabledKeepsNoTrailAndReportsIt verifies the honest disabled
// posture: no log file is created, the service records to the no-op logger, and
// the admin endpoint says the trail is unavailable rather than claiming it is
// empty.
func TestAuditTrail_DisabledKeepsNoTrailAndReportsIt(t *testing.T) {
	disabled := false
	trail := newAuditTrail(t, config.ACMEAuditConfig{Enabled: &disabled})
	require.False(t, trail.logger.Enabled())

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	_, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	payload := RevokeCertRequest{Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw)}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/revoke-cert", payload, true, account.ID)
	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, "a disabled trail must not break issuance or revocation")

	_, err := os.Stat(trail.logPath)
	assert.True(t, os.IsNotExist(err), "a disabled trail must not create a log file")

	queryResp := trail.query(t, "")
	assert.Equal(t, http.StatusNotImplemented, queryResp.Code)
	assert.Contains(t, queryResp.Body.String(), "no audit trail configured")
}

// TestAuditTrail_UnwritableLogPathFails verifies that an enabled trail whose
// log file cannot be opened is a hard failure. A CA must not start when it
// cannot record what it signs.
func TestAuditTrail_UnwritableLogPathFails(t *testing.T) {
	dataDir := t.TempDir()

	// A directory where the log file belongs cannot be opened for writing,
	// regardless of the uid the tests run as.
	logPath := filepath.Join(dataDir, "audit.log")
	require.NoError(t, os.Mkdir(logPath, 0o750))

	cfg := config.ACMEAuditConfig{LogPath: logPath}.AuditConfig(dataDir)
	logger, err := audit.NewFileAuditLogger(cfg)
	require.Error(t, err)
	assert.Nil(t, logger)
	assert.Contains(t, err.Error(), "audit log file")
}

// TestRestService_AuditLoggerDefaultsToNoOp verifies that a service built
// without an audit logger still has one, so no call site has to guard against
// a nil trail.
func TestRestService_AuditLoggerDefaultsToNoOp(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	require.NotNil(t, service.AuditLogger())
	assert.False(t, service.AuditLogger().Enabled())

	// Restoring a nil logger must not leave the service unable to record.
	service.SetAuditLogger(nil)
	require.NotNil(t, service.AuditLogger())
	assert.False(t, service.AuditLogger().Enabled())
	assert.Equal(t, service.AuditLogger(), service.params.AuditLogger)
}

// TestAuditTrail_WriteFailureFailsSecurityOperation verifies the issue #688
// audit write-failure policy: EventCertificateRevoked is SeveritySecurity,
// so a broken audit writer must fail the request (HTTP 500) rather than let
// a security-relevant ACME operation report success while its audit record
// is lost. The CA-side revocation and the ACME record's Status update both
// happen before the audit write in RevokeCertHandler, so the certificate is
// still revoked in storage; what the client does not get is confirmation
// that the operation is safe to consider durable and audited.
func TestAuditTrail_WriteFailureFailsSecurityOperation(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	acmeCert, x509Cert := createTestCertificateWithAuthorization(t, service, key, account.ID)

	// Closing the logger makes every subsequent Log return ErrLoggerClosed.
	require.NoError(t, trail.logger.Close())
	require.ErrorIs(t, trail.logger.Log(context.Background(), &audit.AuditEvent{}), audit.ErrLoggerClosed)

	payload := RevokeCertRequest{Certificate: base64.RawURLEncoding.EncodeToString(x509Cert.Raw)}
	req := createJWSRequest(t, service, key, service.baseRESTURI+"/acme/revoke-cert", payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.RevokeCertHandler(resp, req)
	require.Equal(t, http.StatusInternalServerError, resp.Code)

	certificateDAO, err := service.storageFactory.CertificateDAO()
	require.NoError(t, err)
	updated, err := certificateDAO.Get(req.Context(), acmeCert.ID)
	require.NoError(t, err)
	assert.Equal(t, common.StatusRevoked, updated.Status)
}

// TestAuditTrail_InvalidNonceIsRecorded verifies that parseKID records
// audit.EventInvalidNonce when the JWS carries a nonce the server never
// issued or has already consumed.
func TestAuditTrail_InvalidNonceIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	// A nonce the server never issued is indistinguishable, at redemption
	// time, from one it issued and already consumed: both fail decryption
	// or the used-map check in pkg/acme/nonce.Service.Redeem. Sign with a
	// literal, never-issued nonce rather than a real one later invalidated,
	// exercising the same "unknown nonce" path a replayed or forged nonce
	// would take.
	url := fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID)
	signerOpts := &jose.SignerOptions{
		NonceSource: &staticNonceSource{nonce: "invalid-nonce-not-in-store"},
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
			"kid": url,
		},
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       key.PrivateKey,
	}, signerOpts)
	require.NoError(t, err)

	jws, err := signer.Sign([]byte(""))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, url, strings.NewReader(jws.FullSerialize()))
	req.Header.Set("Content-Type", "application/jose+json")

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)

	page := trail.expectEvents(t, "event_type=INVALID_NONCE", 1)
	require.Len(t, page.Items, 1)
	assert.Equal(t, audit.ResultFailure, page.Items[0].Result)
}

// TestAuditTrail_InvalidSignatureIsRecorded verifies that parseKID records
// audit.EventInvalidSignature when the JWS is signed by a key other than
// the account's registered key — an impersonation attempt.
func TestAuditTrail_InvalidSignatureIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	accountKey := generateTestKey(t)
	account := createTestAccount(t, service, accountKey)

	impostorKey := generateTestKey(t)
	// Sign with a different key than the one registered for account.ID, so
	// jws.Verify(publicKey) fails against the stored account key.
	req := createJWSRequest(t, service, impostorKey,
		fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID), nil, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)

	page := trail.expectEvents(t, "event_type=INVALID_SIGNATURE", 1)
	require.Len(t, page.Items, 1)
	assert.Equal(t, audit.ResultFailure, page.Items[0].Result)
}

// TestAuditTrail_AccountDeactivatedIsRecorded verifies that AccountHandler
// records audit.EventAccountDeactivated when an account deactivates itself
// per RFC 8555 Section 7.3.6.
func TestAuditTrail_AccountDeactivatedIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	req := createJWSRequest(t, service, key,
		fmt.Sprintf("%s/acme/account/%d", service.baseRESTURI, account.ID),
		AccountRequest{Status: common.StatusDeactivated}, true, account.ID)

	resp := httptest.NewRecorder()
	service.AccountHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	page := trail.expectEvents(t, "event_type=ACCOUNT_DEACTIVATED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, auditAccountRef(account.ID), event.Actor)
	assert.Equal(t, "deactivate", event.Action)
	assert.Equal(t, audit.ResultSuccess, event.Result)
}

// TestAuditTrail_ChallengeFailureIsRecorded verifies that ChallengeHandler
// records audit.EventChallengeFailed when the registered challenge
// verifier rejects the response — the single branch every challenge
// validation failure (wrong token, unreachable domain, rejected
// attestation, ...) funnels through.
func TestAuditTrail_ChallengeFailureIsRecorded(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	verifyErr := errors.New("simulated verification failure")
	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return verifyErr
	}

	order := createTestOrderSimple(t, service, account.ID)
	authz := createTestAuthorization(t, service, account, order,
		entities.ACMEIdentifier{Type: "dns", Value: "example.com"},
		[]string{"http-01"})

	// createTestOrderSimple seeds a placeholder authz URL; point the order
	// at the authorization actually created above so ChallengeHandler's
	// order-status update (after recording the failure) resolves it.
	order.Authorizations = []string{authz.URL}
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(context.Background(), order))

	challengeID := authz.Challenges[0].ID
	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, challengeID)
	req := createJWSRequest(t, service, key, url, json.RawMessage(`{}`), true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code, "body: %s", resp.Body.String())

	page := trail.expectEvents(t, "event_type=CHALLENGE_FAILED", 1)
	require.Len(t, page.Items, 1)

	event := page.Items[0]
	assert.Equal(t, auditAccountRef(account.ID), event.Actor)
	assert.Equal(t, "validate", event.Action)
	assert.Equal(t, audit.ResultFailure, event.Result)
	assert.Equal(t, "http-01", event.Details["challenge_type"])
}

// TestAuditKeyFingerprint verifies the account-key identifier recorded on key
// rollover, including the unmarshalable-key path that must still yield a record.
func TestAuditKeyFingerprint(t *testing.T) {
	key := generateTestKey(t)

	fingerprint := auditKeyFingerprint(key.PublicKey)
	assert.NotEmpty(t, fingerprint)
	assert.NotEqual(t, "unknown", fingerprint)
	assert.Equal(t, fingerprint, auditKeyFingerprint(key.PublicKey), "must be stable for one key")

	other := generateTestKey(t)
	assert.NotEqual(t, fingerprint, auditKeyFingerprint(other.PublicKey))

	assert.Equal(t, "unknown", auditKeyFingerprint(nil))
	assert.Equal(t, "unknown", auditKeyFingerprint("not a public key"))
}

// TestAuditValidityDays verifies the issued-lifetime detail, including the
// nonsensical inputs that must not produce a negative validity.
func TestAuditValidityDays(t *testing.T) {
	assert.Equal(t, 0, auditValidityDays(nil))

	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ninetyDays := &x509.Certificate{NotBefore: notBefore, NotAfter: notBefore.Add(90 * 24 * time.Hour)}
	assert.Equal(t, 90, auditValidityDays(ninetyDays))

	// An expiry before the start date is meaningless; report zero rather than
	// writing a negative lifetime into the trail.
	inverted := &x509.Certificate{NotBefore: notBefore, NotAfter: notBefore.Add(-time.Hour)}
	assert.Equal(t, 0, auditValidityDays(inverted))
}
