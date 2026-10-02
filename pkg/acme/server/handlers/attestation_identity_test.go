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

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// attestationChallengeTypes are the challenge types go-xkms#828 binds an
// attested identity for. Every behavior below must hold for each of them
// alike: ChallengeHandler enforces it, not any one verifier.
var attestationChallengeTypes = []string{
	common.ChallengeTypeEnroll01,
	common.ChallengeTypeEndorse01,
	common.ChallengeTypeDeviceAttest01,
}

// runAttestationChallenge posts the challenge of challengeType for an order
// authorizing identifier and returns the stored challenge.
func runAttestationChallenge(
	t *testing.T,
	service *RestService,
	challengeType string,
	identifier entities.ACMEIdentifier,
) entities.ACMEChallenge {
	t.Helper()

	// These tests are about the identity comparison every attestation type
	// shares; the EAB step in front of endorse-01 has its own tests
	// (endorse_challenge_test.go), so it is waived here.
	service.endorseEABRequired = false

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)
	order := createTestOrderWithIdentifiers(t, service, account, []entities.ACMEIdentifier{identifier})
	authz := createTestAuthorizationWithChallenges(t, service, account, order, identifier, []string{challengeType})

	url := fmt.Sprintf("%s/acme/challenge/%d", service.baseRESTURI, authz.Challenges[0].ID)
	req := createJWSRequest(t, service, key, url, map[string]interface{}{}, true, account.ID)
	resp := httptest.NewRecorder()
	service.ChallengeHandler(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	authzDAO, err := service.storageFactory.AuthorizationDAO(account.ID)
	require.NoError(t, err)
	stored, err := authzDAO.Get(context.Background(), authz.ID)
	require.NoError(t, err)
	require.Equal(t, body.Status, stored.Challenges[0].Status)
	return stored.Challenges[0]
}

// attesting returns a verifier that attests identity, records every call in
// *calls, and returns record as the evidence to persist.
func attesting(identity string, record *entities.DeviceAttestation, calls *int) common.AttestingVerifier {
	return common.AttestingVerifierFunc(func(
		_ *net.Resolver, _ common.CertificateAuthority, _ common.AttestationChallenge,
	) (*common.AttestedIdentity, error) {
		*calls++
		return &common.AttestedIdentity{Identifier: identity, Attestation: record}, nil
	})
}

func permanentIdentifier(value string) entities.ACMEIdentifier {
	return entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: value}
}

// TestChallengeHandler_Attestation_IdentityMismatchUnauthorized is go-xkms#828
// for every attestation challenge type: a verifier that attests device A,
// against an order for identifier B, leaves the challenge invalid with an
// unauthorized problem that repeats neither identity, and persists nothing.
func TestChallengeHandler_Attestation_IdentityMismatchUnauthorized(t *testing.T) {
	for _, challengeType := range attestationChallengeTypes {
		t.Run(challengeType, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()
			var calls int
			evidence := &entities.DeviceAttestation{Format: "dice", DeviceIdentityValue: "device-A"}
			service.attestingVerifiers = map[string]common.AttestingVerifier{
				challengeType: attesting("device-A", evidence, &calls),
			}

			got := runAttestationChallenge(t, service, challengeType, permanentIdentifier("device-B"))

			assert.Equal(t, 1, calls, "the verifier must have run: the refusal is the identity comparison")
			assert.Equal(t, common.StatusInvalid, got.Status)
			require.NotNil(t, got.Error)
			assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", got.Error.Type)
			assert.NotContains(t, got.Error.Detail, "device-A")
			assert.NotContains(t, got.Error.Detail, "device-B")
			assert.Nil(t, got.DeviceAttestation, "evidence for the wrong device must not be persisted")
		})
	}
}

// TestChallengeHandler_Attestation_MatchingIdentitySucceeds is the positive
// direction: the attested identity is the order's identifier, so the
// challenge validates and the verifier's evidence is persisted on it.
func TestChallengeHandler_Attestation_MatchingIdentitySucceeds(t *testing.T) {
	for _, challengeType := range attestationChallengeTypes {
		t.Run(challengeType, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()
			var calls int
			evidence := &entities.DeviceAttestation{Format: "dice", DeviceIdentityValue: "device-B"}
			service.attestingVerifiers = map[string]common.AttestingVerifier{
				challengeType: attesting("device-B", evidence, &calls),
			}

			got := runAttestationChallenge(t, service, challengeType, permanentIdentifier("device-B"))

			assert.Equal(t, 1, calls)
			assert.Equal(t, common.StatusValid, got.Status)
			require.NotNil(t, got.DeviceAttestation)
			assert.Equal(t, "device-B", got.DeviceAttestation.DeviceIdentityValue)
		})
	}
}

// TestChallengeHandler_Attestation_PlainVerifierRefused proves the handler
// fails closed: a plain ChallengeVerifierFunc registered for an attestation
// challenge type cannot report an identity, so it is never run and the
// challenge is refused as unauthorized.
func TestChallengeHandler_Attestation_PlainVerifierRefused(t *testing.T) {
	for _, challengeType := range attestationChallengeTypes {
		t.Run(challengeType, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()
			var calls int
			service.challengeMap[challengeType] = func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
				calls++
				return nil
			}

			got := runAttestationChallenge(t, service, challengeType, permanentIdentifier("device-B"))

			assert.Zero(t, calls, "a verifier that cannot report an identity must never run")
			assert.Equal(t, common.StatusInvalid, got.Status)
			require.NotNil(t, got.Error)
			assert.Equal(t, "urn:ietf:params:acme:error:unauthorized", got.Error.Type)
		})
	}
}

// TestChallengeHandler_Attestation_IPIdentifierRefused proves an attestation
// challenge never authorizes an "ip" identifier: the verifier is not run,
// even when the identity it would attest equals the address.
func TestChallengeHandler_Attestation_IPIdentifierRefused(t *testing.T) {
	for _, challengeType := range attestationChallengeTypes {
		t.Run(challengeType, func(t *testing.T) {
			service, _, cleanup := setupTestService(t)
			defer cleanup()
			var calls int
			service.attestingVerifiers = map[string]common.AttestingVerifier{
				challengeType: attesting("192.0.2.1", nil, &calls),
			}
			ip := entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "192.0.2.1"}

			got := runAttestationChallenge(t, service, challengeType, ip)

			assert.Zero(t, calls, "the verifier must not run for an ip identifier")
			assert.Equal(t, common.StatusInvalid, got.Status)
			require.NotNil(t, got.Error)
			assert.Equal(t, "urn:ietf:params:acme:error:unsupportedIdentifier", got.Error.Type)
			assert.Contains(t, got.Error.Detail, challengeType)
		})
	}
}

// TestChallengeHandler_Attestation_VerifierWithoutIdentityRefused proves a
// verifier that reports success with no identity is a defect refused as a
// server error, never accepted.
func TestChallengeHandler_Attestation_VerifierWithoutIdentityRefused(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.attestingVerifiers = map[string]common.AttestingVerifier{
		common.ChallengeTypeEnroll01: common.AttestingVerifierFunc(func(
			*net.Resolver, common.CertificateAuthority, common.AttestationChallenge,
		) (*common.AttestedIdentity, error) {
			return nil, nil
		}),
	}

	got := runAttestationChallenge(t, service, common.ChallengeTypeEnroll01, permanentIdentifier("device-B"))

	assert.Equal(t, common.StatusInvalid, got.Status)
	require.NotNil(t, got.Error)
	assert.Equal(t, "urn:ietf:params:acme:error:serverInternal", got.Error.Type)
}

// TestChallengeHandler_Attestation_VerifierErrorRefused proves a verifier
// error fails the challenge without disclosing its text to the client.
func TestChallengeHandler_Attestation_VerifierErrorRefused(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.attestingVerifiers = map[string]common.AttestingVerifier{
		common.ChallengeTypeEnroll01: common.AttestingVerifierFunc(func(
			*net.Resolver, common.CertificateAuthority, common.AttestationChallenge,
		) (*common.AttestedIdentity, error) {
			return nil, &ErrDeviceAttestationNotFound{OrderID: 9}
		}),
	}

	got := runAttestationChallenge(t, service, common.ChallengeTypeEnroll01, permanentIdentifier("device-B"))

	assert.Equal(t, common.StatusInvalid, got.Status)
	require.NotNil(t, got.Error)
	assert.NotContains(t, got.Error.Detail, "order 9")
}

// TestChallengeHandler_NonAttestationUsesChallengeVerifierFunc proves the
// ruling leaves http-01 untouched: it is still served by the plain verifier
// map, and a registered attesting verifier does not shadow it.
func TestChallengeHandler_NonAttestationUsesChallengeVerifierFunc(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()
	var calls int
	service.challengeMap["http-01"] = func(_ *net.Resolver, _ common.CertificateAuthority, domain, _, _, _ string) error {
		calls++
		return nil
	}
	dns := entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"}

	got := runAttestationChallenge(t, service, "http-01", dns)

	assert.Equal(t, 1, calls)
	assert.Equal(t, common.StatusValid, got.Status)
	assert.Nil(t, got.DeviceAttestation)
}
