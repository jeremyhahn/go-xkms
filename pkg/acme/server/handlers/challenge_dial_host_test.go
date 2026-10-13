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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
)

func TestPermanentIdentifierDialHost(t *testing.T) {
	tests := []struct {
		identifier string
		want       string
	}{
		{"10.0.0.1:8301", "10.0.0.1"},
		{"node-1.example.com:8301", "node-1.example.com"},
		{"[2001:db8::1]:8301", "2001:db8::1"},
		{"10.0.0.1", "10.0.0.1"},
		{"node-1.example.com", "node-1.example.com"},
		{"2001:db8::1", "2001:db8::1"},
		{"model-serial", "model-serial"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.identifier, func(t *testing.T) {
			assert.Equal(t, tt.want, permanentIdentifierDialHost(tt.identifier))
		})
	}
}

// runEnroll01Challenge posts an enroll-01 challenge response for an order
// whose permanent-identifier is identifier, from client address 192.0.2.1,
// and returns the challenge the verifier was handed (zero when it was never
// called) and the stored challenge.
func runEnroll01Challenge(t *testing.T, identifier string, allowLoopback bool) (common.AttestationChallenge, entities.ACMEChallenge) {
	t.Helper()
	service, _, cleanup := setupTestService(t)
	t.Cleanup(cleanup)
	service.allowLoopbackIdentifier = allowLoopback

	var seen common.AttestationChallenge
	service.attestingVerifiers = map[string]common.AttestingVerifier{
		common.ChallengeTypeEnroll01: common.AttestingVerifierFunc(func(
			_ *net.Resolver, _ common.CertificateAuthority, challenge common.AttestationChallenge,
		) (*common.AttestedIdentity, error) {
			seen = challenge
			return &common.AttestedIdentity{Identifier: challenge.IdentifierValue}, nil
		}),
	}

	accountKey := generateTestKey(t)
	account := createTestAccount(t, service, accountKey)
	id := entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: identifier}
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{id})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, id,
		[]string{common.ChallengeTypeEnroll01})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, accountKey, url, map[string]interface{}{}, true, account.ID)
	req.RemoteAddr = "192.0.2.1:12345"
	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)
	stored, err := authzDAO.Get(context.Background(), authz.ID)
	require.NoError(t, err)
	return seen, stored.Challenges[0]
}

// TestChallengeHandler_Enroll01_DialsRaftAddressHost pins the cluster join
// contract: a joiner's permanent-identifier is its Raft address, and the
// server reaches the device at that host on the challenge port, while the
// identity compared and recorded stays the full host:port.
func TestChallengeHandler_Enroll01_DialsRaftAddressHost(t *testing.T) {
	seen, stored := runEnroll01Challenge(t, "198.51.100.7:8301", false)

	require.Equal(t, common.StatusValid, stored.Status)
	assert.Equal(t, "198.51.100.7", seen.DialTarget)
	assert.Equal(t, "8080", seen.Port, "the device answers on the challenge port, not the Raft port")
	assert.Equal(t, "198.51.100.7:8301", seen.IdentifierValue)
}

// TestChallengeHandler_Enroll01_LoopbackRaftAddressGated verifies a port does
// not smuggle the loopback identifier past acme.enrollment.allow_loopback_identifier:
// 127.0.0.1:<port> is refused without the flag and, with it, is dialled at the
// client's own address like the bare loopback identifier.
func TestChallengeHandler_Enroll01_LoopbackRaftAddressGated(t *testing.T) {
	seen, stored := runEnroll01Challenge(t, loopbackIdentifier+":8301", false)
	require.Equal(t, common.StatusInvalid, stored.Status)
	assert.Empty(t, seen.DialTarget, "a refused loopback identifier must never be dialled")

	seen, stored = runEnroll01Challenge(t, loopbackIdentifier+":8301", true)
	require.Equal(t, common.StatusValid, stored.Status)
	assert.Equal(t, "192.0.2.1", seen.DialTarget)
}
