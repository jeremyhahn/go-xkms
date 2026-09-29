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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/netguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChallengeProblem(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		wantType   string
		wantDetail string
	}{
		{
			name:       "refused target reads as a connection failure",
			err:        &validation.Error{Kind: validation.KindTargetRefused, Err: &netguard.AddressNotPermittedError{Address: "10.20.30.40:8080"}},
			wantType:   common.ErrTypeConnectionError,
			wantDetail: "Challenge validation failed: connection failed",
		},
		{
			name:       "dial error",
			err:        &validation.Error{Kind: validation.KindConnection, Err: errors.New("dial tcp 192.168.7.7:9000: connect: connection refused")},
			wantType:   common.ErrTypeConnectionError,
			wantDetail: "Challenge validation failed: connection failed",
		},
		{
			name:       "status",
			err:        &validation.Error{Kind: validation.KindStatus, Err: &validation.StatusError{StatusCode: 401}},
			wantType:   common.ErrTypeConnectionError,
			wantDetail: "Challenge validation failed: unexpected HTTP status",
		},
		{
			name:       "invalid target",
			err:        &validation.Error{Kind: validation.KindInvalidTarget, Err: errors.New("bad host")},
			wantType:   common.ErrTypeIncorrectResponse,
			wantDetail: "Challenge validation failed: invalid validation target",
		},
		{
			name:       "wrapped by a decorator",
			err:        fmt.Errorf("breaker: %w", &validation.Error{Kind: validation.KindResponseTooLarge}),
			wantType:   common.ErrTypeConnectionError,
			wantDetail: "Challenge validation failed: response too large",
		},
		{
			name:       "any other verifier error",
			err:        errors.New("enroll-01: tcg-csr from internal-ca.corp.example failed: x509: unknown authority"),
			wantType:   common.ErrTypeIncorrectResponse,
			wantDetail: "Challenge validation failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problem := challengeProblem(tc.err)
			assert.Equal(t, "urn:ietf:params:acme:error:"+tc.wantType, problem.Type)
			assert.Equal(t, tc.wantDetail, problem.Detail)
		})
	}
}

// TestChallengeHandler_VerifierErrorIsNotShownToClient drives the handler
// end to end: the verifier's error names an internal address and a dial
// failure, and the challenge the client reads back carries only the fixed
// category.
func TestChallengeHandler_VerifierErrorIsNotShownToClient(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	const internalDetail = "dial tcp 10.20.30.40:8080: address not permitted"
	service.challengeMap["http-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, domain, port, token, keyAuth string) error {
		return &validation.Error{
			Kind: validation.KindTargetRefused,
			Err:  errors.New(internalDetail),
		}
	}

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	identifier := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "device.example.com"}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{"http-01"})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	raw := resp.Body.String()
	assert.NotContains(t, raw, "10.20.30.40", "the dialed address must not reach the client")
	assert.NotContains(t, raw, "dial tcp")

	var challengeResp struct {
		Status string          `json:"status"`
		Error  *entities.Error `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &challengeResp))
	assert.Equal(t, common.StatusInvalid, challengeResp.Status)
	require.NotNil(t, challengeResp.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:"+common.ErrTypeConnectionError, challengeResp.Error.Type)
	assert.Equal(t, "Challenge validation failed: connection failed", challengeResp.Error.Detail)
}
