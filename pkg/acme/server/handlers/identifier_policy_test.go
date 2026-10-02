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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strictPolicyConfig returns a PolicyConfig exercising every enforcement
// tier the identifier policy table test below checks: a high-risk domain
// blocklist entry (cascades to its subdomains and to wildcard issuance for
// the domain), an exact FQDN blocklist entry (cascades to wildcard issuance
// for its parent), a blocked CIDR, public-suffix enforcement, and
// reserved-IP rejection.
func strictPolicyConfig() *policy.PolicyConfig {
	return &policy.PolicyConfig{
		Blocklist: policy.BlocklistConfig{
			HighRiskBlockedNames: []string{"blocked.example.com"},
			ExactBlockedNames:    []string{"exact.example.com"},
			AdminBlockedPrefixes: []string{"203.0.113.0/24"},
		},
		EnabledIdentifierTypes: map[string]bool{
			policy.IdentifierTypeDNS:                 true,
			policy.IdentifierTypeIP:                  true,
			policy.IdentifierTypePermanentIdentifier: true,
		},
		EnabledChallengeTypes: map[string]bool{
			policy.ChallengeTypeHTTP01:         true,
			policy.ChallengeTypeDNS01:          true,
			policy.ChallengeTypeTLSALPN01:      true,
			policy.ChallengeTypeDeviceAttest01: true,
			policy.ChallengeTypeEnroll01:       true,
			policy.ChallengeTypeEndorse01:      true,
		},
		RequirePublicSuffix: true,
		AllowWildcards:      true,
		RejectReservedIPs:   true,
	}
}

// TestNewOrderHandler_IdentifierPolicy exercises every RFC 8555 outcome the
// identifier policy engine can produce at order-creation time: a blocklist
// refusal (domain, FQDN, wildcard cascade, CIDR), a reserved/loopback IP
// refusal, a public-suffix refusal, a syntactically malformed identifier,
// and an identifier the policy allows.
func TestNewOrderHandler_IdentifierPolicy(t *testing.T) {
	tests := []struct {
		name        string
		identifier  entities.ACMEIdentifier
		wantStatus  int
		wantErrType string
	}{
		{
			name:        "blocked domain cascades to subdomain",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "sub.blocked.example.com"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			name:        "blocked exact FQDN",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "exact.example.com"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			name:        "wildcard blocked by domain blocklist cascade",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "*.blocked.example.com"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			name:        "IP blocked by CIDR",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "203.0.113.5"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			name:        "reserved IP rejected",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "169.254.1.1"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			name:        "loopback IP rejected",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "127.0.0.1"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			// "co.uk" is itself a listed public suffix (a two-label PSL
			// entry): it has no label beyond the suffix, so it fails
			// public-suffix enforcement even though every character and
			// label is syntactically valid.
			name:        "non-public-suffix domain rejected",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "co.uk"},
			wantStatus:  http.StatusForbidden,
			wantErrType: common.ErrTypeRejectedIdentifier,
		},
		{
			name:        "malformed domain",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "-invalid-.example.com"},
			wantStatus:  http.StatusBadRequest,
			wantErrType: common.ErrTypeMalformedError,
		},
		{
			name:        "malformed IP",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "not-an-ip"},
			wantStatus:  http.StatusBadRequest,
			wantErrType: common.ErrTypeMalformedError,
		},
		{
			name:        "allowed identifier",
			identifier:  entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "allowed.example.org"},
			wantStatus:  http.StatusCreated,
			wantErrType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _, cleanup := setupTestServiceWithPolicy(t, strictPolicyConfig())
			defer cleanup()

			service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return nil
			}
			service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return nil
			}
			service.challengeMap["tls-alpn-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
				return nil
			}

			key := generateTestKey(t)
			account := createTestAccount(t, service, key)

			payload := NewOrderRequest{Identifiers: []entities.ACMEIdentifier{tt.identifier}}
			url := service.baseRESTURI + "/acme/new-order"
			req := createJWSRequest(t, service, key, url, payload, true, account.ID)

			resp := httptest.NewRecorder()
			service.NewOrderHandler(resp, req)

			if tt.wantErrType == "" {
				require.Equal(t, tt.wantStatus, resp.Code, resp.Body.String())
				return
			}
			assertErrorType(t, resp, tt.wantErrType, tt.wantStatus)
		})
	}
}

// TestNewOrderHandler_IdentifierTypeDisabled verifies that an identifier
// type disabled by policy configuration is refused at order-creation time,
// distinctly from an identifier type the ACME server never supports at all.
func TestNewOrderHandler_IdentifierTypeDisabled(t *testing.T) {
	cfg := strictPolicyConfig()
	cfg.EnabledIdentifierTypes[policy.IdentifierTypeIP] = false

	service, _, cleanup := setupTestServiceWithPolicy(t, cfg)
	defer cleanup()

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	payload := NewOrderRequest{
		Identifiers: []entities.ACMEIdentifier{
			{Type: common.AuthzTypeIP, Value: "198.51.100.7"},
		},
	}
	url := service.baseRESTURI + "/acme/new-order"
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)

	resp := httptest.NewRecorder()
	service.NewOrderHandler(resp, req)

	assertErrorType(t, resp, common.ErrTypeUnsupportedIdentifier, http.StatusBadRequest)
}

// TestCreateChallenges_PolicyOverride verifies that
// PolicyConfig.IdentifierChallengeTypes overrides go-xkms's default
// challenge candidates for an identifier type, per identifier type, without
// affecting identifier types the override does not name.
func TestCreateChallenges_PolicyOverride(t *testing.T) {
	cfg := strictPolicyConfig()
	cfg.IdentifierChallengeTypes = map[string][]string{
		policy.IdentifierTypeIP: {policy.ChallengeTypeHTTP01, policy.ChallengeTypeTLSALPN01},
	}

	service, _, cleanup := setupTestServiceWithPolicy(t, cfg)
	defer cleanup()

	service.challengeMap["http-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["dns-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	service.challengeMap["tls-alpn-01"] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	}
	registerLegacyAttesting(service, "enroll-01", func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
		return nil
	})

	// The override applies to IP: http-01 and tls-alpn-01, not the default
	// enrollment challenges.
	ipChallenges, err := service.createChallenges(1, 2, entities.ACMEIdentifier{
		Type: common.AuthzTypeIP, Value: "198.51.100.7",
	}, false)
	require.NoError(t, err)
	gotTypes := make([]string, 0, len(ipChallenges))
	for _, c := range ipChallenges {
		gotTypes = append(gotTypes, c.Type)
	}
	assert.ElementsMatch(t, []string{policy.ChallengeTypeHTTP01, policy.ChallengeTypeTLSALPN01}, gotTypes)

	// DNS keeps go-xkms's default (http-01, dns-01): the override did not
	// name it.
	dnsChallenges, err := service.createChallenges(1, 2, entities.ACMEIdentifier{
		Type: common.AuthzTypeDNS, Value: "example.com",
	}, false)
	require.NoError(t, err)
	gotDNSTypes := make([]string, 0, len(dnsChallenges))
	for _, c := range dnsChallenges {
		gotDNSTypes = append(gotDNSTypes, c.Type)
	}
	assert.ElementsMatch(t, []string{policy.ChallengeTypeHTTP01, policy.ChallengeTypeDNS01}, gotDNSTypes)
}

// TestCreateChallenges_DefaultIdentifierChallengeTypes verifies go-xkms's
// default candidate challenge types for every identifier type, including
// the non-configurable wildcard-DNS restriction to dns-01, when no policy
// override is supplied (Params.Policy is nil).
func TestCreateChallenges_DefaultIdentifierChallengeTypes(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	for _, ct := range []string{"http-01", "dns-01"} {
		service.challengeMap[ct] = func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return nil
		}
	}
	for _, ct := range []string{"enroll-01", "endorse-01", "device-attest-01"} {
		registerLegacyAttesting(service, ct, func(resolver *net.Resolver, ca common.CertificateAuthority, authzValue, challengePort, challengeToken, expectedKeyAuth string) error {
			return nil
		})
	}

	tests := []struct {
		name       string
		identifier entities.ACMEIdentifier
		isWildcard bool
		want       []string
		wantNone   bool
	}{
		{
			name:       "dns non-wildcard",
			identifier: entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "example.com"},
			want:       []string{"http-01", "dns-01"},
		},
		{
			name:       "dns wildcard",
			identifier: entities.ACMEIdentifier{Type: common.AuthzTypeDNS, Value: "*.example.com"},
			isWildcard: true,
			want:       []string{"dns-01"},
		},
		{
			// go-xkms#828: an attestation challenge never authorizes an ip
			// identifier, so none is offered for one.
			name:       "ip",
			identifier: entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "198.51.100.7"},
			wantNone:   true,
		},
		{
			name:       "permanent-identifier",
			identifier: entities.ACMEIdentifier{Type: common.AuthzTypePermanentIdentifier, Value: "device-123"},
			want:       []string{"enroll-01", "endorse-01", "device-attest-01"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenges, err := service.createChallenges(1, 2, tt.identifier, tt.isWildcard)
			if tt.wantNone {
				require.ErrorAs(t, err, new(*ErrIPIdentifierNotValidatable))
				require.Empty(t, challenges)
				return
			}
			require.NoError(t, err)
			got := make([]string, 0, len(challenges))
			for _, c := range challenges {
				got = append(got, c.Type)
			}
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

// An "ip" override that names a challenge no verifier is registered for must
// not fall back to offering an attestation challenge, which ChallengeHandler
// refuses for every ip identifier: the identifier is declined instead.
func TestCreateChallenges_IPOverrideWithoutARegisteredVerifierIsDeclined(t *testing.T) {
	cfg := strictPolicyConfig()
	cfg.IdentifierChallengeTypes = map[string][]string{
		policy.IdentifierTypeIP: {policy.ChallengeTypeHTTP01, policy.ChallengeTypeDeviceAttest01},
	}
	service, _, cleanup := setupTestServiceWithPolicy(t, cfg)
	defer cleanup()
	registerLegacyAttesting(service, "device-attest-01", func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		return nil
	})
	ip := entities.ACMEIdentifier{Type: common.AuthzTypeIP, Value: "198.51.100.7"}

	challenges, err := service.createChallenges(1, 2, ip, false)
	require.ErrorAs(t, err, new(*ErrIPIdentifierNotValidatable))
	require.Empty(t, challenges)

	// With http-01 registered, it alone is offered.
	service.challengeMap["http-01"] = func(*net.Resolver, common.CertificateAuthority, string, string, string, string) error {
		return nil
	}
	challenges, err = service.createChallenges(1, 2, ip, false)
	require.NoError(t, err)
	require.Len(t, challenges, 1)
	assert.Equal(t, policy.ChallengeTypeHTTP01, challenges[0].Type)
}
