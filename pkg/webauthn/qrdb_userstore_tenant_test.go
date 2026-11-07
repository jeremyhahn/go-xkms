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

package webauthn

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// tenantRP is one tenant's relying party over storage shared with others.
type tenantRP struct {
	users UserStore
	svc   *Service
}

// newTenantRPs builds a relying party per tenant on one user client, one
// DAOFactory and one KV, as tenant-scoped relying parties share them in a
// node. The user client reads users in every tenant, as the service
// binding does in qrdb.
func newTenantRPs(t *testing.T, cfg *Config, tenants ...string) map[string]tenantRP {
	t.Helper()
	users := &boundUserClient{fakeUserClient: newFakeUserClient()}
	factory := newTestDAOFactory()
	kv := testutil.NewQRDBFakeTransport()
	rps := make(map[string]tenantRP, len(tenants))
	for _, tenant := range tenants {
		us, creds, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
			Users:       users,
			DAOFactory:  factory,
			KV:          kv,
			TenantID:    tenant,
			CallContext: bindForTest,
		})
		require.NoError(t, err)
		svc, err := NewService(ServiceParams{
			Config:          cfg,
			UserStore:       us,
			SessionStore:    NewMemorySessionStore(),
			CredentialStore: creds,
		})
		require.NoError(t, err)
		rps[tenant] = tenantRP{users: us, svc: svc}
	}
	return rps
}

func TestQRDBUserStore_LoginHandleFromAnotherTenantResolvesToNoUser(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
		ResidentKeyRequirement:  "preferred",
	}
	rps := newTenantRPs(t, cfg, "tenant-a", "tenant-b")
	tenantA, tenantB := rps["tenant-a"], rps["tenant-b"]
	rp := virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]}

	// Register a passkey in tenant A.
	credential := newEC2Credential(t)
	regOptions, regSessionID, err := tenantA.svc.BeginRegistration(ctx, "alice@example.com", "Alice")
	require.NoError(t, err)
	regOptionsJSON, err := json.Marshal(regOptions.Response)
	require.NoError(t, err)
	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(), credential, *parsedRegOptions)
	parsedAttestation, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, alice, err := tenantA.svc.FinishRegistration(ctx, regSessionID, parsedAttestation)
	require.NoError(t, err)
	handle := alice.WebAuthnID()

	// A sees its own user; B gets the answer an unknown handle gets.
	_, err = tenantA.users.GetByID(ctx, handle)
	require.NoError(t, err)
	_, err = tenantB.users.GetByID(ctx, handle)
	assert.ErrorIs(t, err, ErrUserNotFound)

	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: handle})
	authenticator.AddCredential(credential)

	// login runs one ceremony at tenant B with A's passkey, and returns
	// the token FinishLogin issued, or the error of the step that refused.
	login := func(t *testing.T, beginHandle []byte) (string, error) {
		t.Helper()
		options, sessionID, err := tenantB.svc.BeginLogin(ctx, beginHandle)
		if err != nil {
			return "", err
		}
		optionsJSON, err := json.Marshal(options.Response)
		require.NoError(t, err)
		parsedOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
		require.NoError(t, err)
		assertion := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *parsedOptions)
		parsedAssertion, err := parseAssertionResponse(assertion)
		require.NoError(t, err)
		token, _, err := tenantB.svc.FinishLogin(ctx, sessionID, handle, parsedAssertion)
		return token, err
	}

	t.Run("handle-based", func(t *testing.T) {
		token, err := login(t, handle)
		require.Error(t, err, "tenant B must not log in tenant A's user by handle")
		require.Empty(t, token)
	})
	t.Run("discoverable", func(t *testing.T) {
		token, err := login(t, nil)
		require.Error(t, err, "tenant B must not log in tenant A's discoverable passkey")
		require.Empty(t, token)
	})
}
