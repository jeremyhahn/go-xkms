//go:build codec_json

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

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingACMEAuditLogger always fails to persist, so the challenge handler's
// attestation-event write-failure handling can be exercised without a real
// backend. It reports Enabled()==true so the handler does not skip the write.
type failingACMEAuditLogger struct {
	err error
}

func (f *failingACMEAuditLogger) Log(_ context.Context, _ *audit.AuditEvent) error {
	return f.err
}

func (f *failingACMEAuditLogger) LogWithContext(
	_ context.Context, _ audit.EventType, _, _, _ string, _ audit.Result, _ map[string]interface{}) error {
	return f.err
}

func (f *failingACMEAuditLogger) Flush() error  { return nil }
func (f *failingACMEAuditLogger) Close() error  { return nil }
func (f *failingACMEAuditLogger) Enabled() bool { return true }

var _ audit.AuditLogger = (*failingACMEAuditLogger)(nil)

// =============================================================================
// EventTPMAttestation (enroll-01)
// =============================================================================

// TestChallengeHandler_EnrollAttestation_EmitsAuditEvent_OnSuccess verifies
// that a successful enroll-01 challenge records a TPM_ATTESTATION event with
// the account, challenge and challenge-type fields, and still transitions
// the challenge to valid.
func TestChallengeHandler_EnrollAttestation_EmitsAuditEvent_OnSuccess(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	registerLegacyAttesting(service, "enroll-01", func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	})

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: "device-attest-1"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01"})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	var challengeResp struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&challengeResp))
	assert.Equal(t, common.StatusValid, challengeResp.Status)

	page := trail.expectEvents(t, "event_type=TPM_ATTESTATION", 1)
	require.Len(t, page.Items, 1)
	assert.Equal(t, auditAccountRef(account.ID), page.Items[0].Actor)
	assert.Equal(t, fmt.Sprintf("challenge:%d", authz.Challenges[0].ID), page.Items[0].Resource)
	assert.Equal(t, "validate", page.Items[0].Action)
	assert.Equal(t, audit.ResultSuccess, page.Items[0].Result)
	assert.Equal(t, "enroll-01", page.Items[0].Details["challenge_type"])
}

// TestChallengeHandler_EnrollAttestation_AuditWriteFailure_FailsChallenge
// verifies that a failed audit write on a successful enroll-01 verification
// refuses the challenge instead of letting an unaudited attestation decision
// stand: the challenge must not transition to valid.
func TestChallengeHandler_EnrollAttestation_AuditWriteFailure_FailsChallenge(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	auditErr := fmt.Errorf("audit backend unavailable")
	service.SetAuditLogger(&failingACMEAuditLogger{err: auditErr})

	registerLegacyAttesting(service, "enroll-01", func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	})

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: "device-attest-2"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"enroll-01"})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	// A failed attestation-event write also fails the subsequent
	// EventChallengeFailed write (same failing logger), so the handler
	// escalates to a hard server error rather than returning a normal
	// challenge body claiming the challenge is valid or even cleanly invalid.
	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)

	// The authorization backing the challenge must not have been promoted
	// to valid: the failed write refuses the whole decision.
	ctx := context.Background()
	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)
	updatedAuthz, err := authzDAO.Get(ctx, authz.ID)
	require.NoError(t, err)
	assert.NotEqual(t, common.StatusValid, updatedAuthz.Status)
}

// =============================================================================
// EventEndorsementVerified (endorse-01)
// =============================================================================

// TestChallengeHandler_EndorseAttestation_EmitsAuditEvent_OnSuccess verifies
// that a successful endorse-01 challenge records an ENDORSEMENT_VERIFIED
// event.
func TestChallengeHandler_EndorseAttestation_EmitsAuditEvent_OnSuccess(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.endorseEABRequired = false // the audit event does not depend on EAB
	service.SetAuditLogger(trail.logger)

	registerLegacyAttesting(service, "endorse-01", func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	})

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: "device-endorse-1"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"endorse-01"})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	var challengeResp struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&challengeResp))
	assert.Equal(t, common.StatusValid, challengeResp.Status)

	page := trail.expectEvents(t, "event_type=ENDORSEMENT_VERIFIED", 1)
	require.Len(t, page.Items, 1)
	assert.Equal(t, "endorse-01", page.Items[0].Details["challenge_type"])
	assert.Equal(t, audit.ResultSuccess, page.Items[0].Result)
}

// TestChallengeHandler_EndorseAttestation_AuditWriteFailure_FailsChallenge
// mirrors the enroll-01 case for endorse-01.
func TestChallengeHandler_EndorseAttestation_AuditWriteFailure_FailsChallenge(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.endorseEABRequired = false // the audit event does not depend on EAB
	auditErr := fmt.Errorf("audit backend unavailable")
	service.SetAuditLogger(&failingACMEAuditLogger{err: auditErr})

	registerLegacyAttesting(service, "endorse-01", func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	})

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: "device-endorse-2"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"endorse-01"})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeServerInternal, http.StatusInternalServerError)
}

// TestChallengeHandler_HTTP01_NoAttestationEvent verifies the attestation
// audit gate is scoped to enroll-01/endorse-01: a plain http-01 success does
// not emit TPM_ATTESTATION or ENDORSEMENT_VERIFIED (it stays covered by the
// existing, informational challenge-lifecycle events).
func TestChallengeHandler_HTTP01_NoAttestationEvent(t *testing.T) {
	trail := newAuditTrail(t, config.ACMEAuditConfig{})
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.SetAuditLogger(trail.logger)

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return nil
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)

	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)

	var challengeResp struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&challengeResp))
	assert.Equal(t, common.StatusValid, challengeResp.Status)

	assert.Equal(t, 0, trail.events(t, "event_type=TPM_ATTESTATION").Total)
	assert.Equal(t, 0, trail.events(t, "event_type=ENDORSEMENT_VERIFIED").Total)
}
