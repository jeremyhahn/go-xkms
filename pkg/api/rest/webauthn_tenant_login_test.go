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

package rest

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

const (
	tenantLoginTenantB = "tenant-b"
	tenantLoginHostB   = "b.example.com"
	tenantLoginEmail   = "bea@example.com"
)

// tenantLoginFixture is a tenant-aware relying party over an embedded
// first-boot node holding the system tenant and tenant-b.
type tenantLoginFixture struct {
	router *webauthn.TenantRouter
	issuer *WebAuthnTokenAdapter
	rp     virtualwebauthn.RelyingParty
	authn  virtualwebauthn.Authenticator
	cred   virtualwebauthn.Credential
	handle []byte
}

func newTenantLoginFixture(t *testing.T) *tenantLoginFixture {
	t.Helper()
	n, err := testutil.NewFirstBootNode(t)
	require.NoError(t, err)
	require.NoError(t, n.ProvisionTenant(tenantLoginTenantB))

	open := true
	cfg := &webauthn.Config{
		RPID:                    "example.com",
		RPDisplayName:           "xkms test",
		RPOrigins:               []string{"https://example.com", "https://" + tenantLoginHostB},
		TenantHosts:             map[string]string{tenantLoginHostB: tenantLoginTenantB},
		AllowPublicRegistration: &open,
	}
	issuer := newTestTokenIssuer(t)
	router, err := BuildWebAuthnTenantRouter(WebAuthnTenantRouterParams{
		Service: WebAuthnServiceParams{
			Config:      cfg,
			QRDBClient:  n.Client(),
			DAOFactory:  newTenantLoginDAOFactory(),
			TokenIssuer: issuer,
		},
		TenantExists: func(_ context.Context, tenantID string) (bool, error) {
			return tenantID == tenantLoginTenantB, nil
		},
	})
	require.NoError(t, err)

	f := &tenantLoginFixture{
		router: router,
		issuer: NewWebAuthnTokenAdapter(issuer, ""),
		rp:     virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
		authn:  virtualwebauthn.NewAuthenticator(),
		cred:   virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	f.enrol(t)
	return f
}

// enrol registers the passkey of a tenant-b account on tenant-b's RP.
func (f *tenantLoginFixture) enrol(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	svc, err := f.router.For(ctx, tenantLoginTenantB)
	require.NoError(t, err)
	opts, sessionID, err := svc.BeginRegistration(ctx, tenantLoginEmail, "Bea")
	require.NoError(t, err)
	raw, err := json.Marshal(opts.Response)
	require.NoError(t, err)
	attOpts, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	require.NoError(t, err)
	att := virtualwebauthn.CreateAttestationResponse(f.rp, f.authn, f.cred, *attOpts)
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(att))
	require.NoError(t, err)
	_, _, err = svc.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)
	f.authn.AddCredential(f.cred)
	user, err := svc.GetUserByEmail(ctx, tenantLoginEmail)
	require.NoError(t, err)
	f.handle = user.WebAuthnID()
}

type loginKind int

const (
	loginByEmail loginKind = iota
	loginByHandle
	loginDiscoverable
)

// begin starts a login of kind on svc.
func (f *tenantLoginFixture) begin(t *testing.T, svc *webauthn.Service, kind loginKind, email string) (*protocol.CredentialAssertion, string) {
	t.Helper()
	ctx := context.Background()
	var (
		opts      *protocol.CredentialAssertion
		sessionID string
		err       error
	)
	switch kind {
	case loginByEmail:
		opts, sessionID, err = svc.BeginLoginForEmail(ctx, email)
	case loginByHandle:
		opts, sessionID, err = svc.BeginLoginForHandle(ctx, f.handle)
	default:
		opts, sessionID, err = svc.BeginLogin(ctx, nil)
	}
	require.NoError(t, err)
	return opts, sessionID
}

// finish answers opts with the enrolled passkey on svc.
func (f *tenantLoginFixture) finish(t *testing.T, svc *webauthn.Service, opts *protocol.CredentialAssertion, sessionID string) (string, error) {
	t.Helper()
	raw, err := json.Marshal(opts.Response)
	require.NoError(t, err)
	asOpts, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	require.NoError(t, err)
	as := virtualwebauthn.CreateAssertionResponse(f.rp, f.authn, f.cred, *asOpts)
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(as))
	require.NoError(t, err)
	token, _, err := svc.FinishLogin(context.Background(), sessionID, nil, parsed)
	return token, err
}

func optionKeys(t *testing.T, opts *protocol.CredentialAssertion) []string {
	t.Helper()
	raw, err := json.Marshal(opts.Response)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestTenantLogin_TokenCarriesTenant proves a tenant-b account signs in on
// tenant-b's RP by email, handle and discoverable credential, and every
// minted token carries tenant-b.
func TestTenantLogin_TokenCarriesTenant(t *testing.T) {
	f := newTenantLoginFixture(t)
	ctx := context.Background()
	for _, kind := range []loginKind{loginByEmail, loginByHandle, loginDiscoverable} {
		svc, err := f.router.For(ctx, tenantLoginTenantB)
		require.NoError(t, err)
		opts, sessionID := f.begin(t, svc, kind, tenantLoginEmail)
		token, err := f.finish(t, svc, opts, sessionID)
		require.NoError(t, err, "kind %d", kind)
		id := authenticateMinted(t, f.issuer, token)
		require.Equal(t, tenantLoginTenantB, id.TenantID, "kind %d", kind)
	}
}

// TestTenantLogin_HostSelectsTenant proves a request with no tenant on a
// host mapped in tenant_hosts reaches the host's tenant.
func TestTenantLogin_HostSelectsTenant(t *testing.T) {
	f := newTenantLoginFixture(t)
	ctx := context.Background()
	svc, err := f.router.ForRequest(ctx, tenantLoginHostB, "")
	require.NoError(t, err)
	opts, sessionID := f.begin(t, svc, loginByEmail, tenantLoginEmail)
	token, err := f.finish(t, svc, opts, sessionID)
	require.NoError(t, err)
	require.Equal(t, tenantLoginTenantB, authenticateMinted(t, f.issuer, token).TenantID)
}

// TestTenantLogin_CrossTenantIsDecoy proves the tenant-b account's factors
// under the system tenant, an unknown tenant, or a host mapped to another
// tenant get a decoy begin shaped like a real one, and finish fails exactly
// as a wrong assertion does; an unknown tenant is never cached.
func TestTenantLogin_CrossTenantIsDecoy(t *testing.T) {
	f := newTenantLoginFixture(t)
	ctx := context.Background()
	b, err := f.router.For(ctx, tenantLoginTenantB)
	require.NoError(t, err)
	realOpts, _ := f.begin(t, b, loginByEmail, tenantLoginEmail)
	realKeys := optionKeys(t, realOpts)

	// Reference: an unknown email in a known tenant.
	refOpts, refSession := f.begin(t, b, loginByEmail, "nobody@example.com")
	require.Equal(t, realKeys, optionKeys(t, refOpts))
	_, refErr := f.finish(t, b, refOpts, refSession)
	require.Error(t, refErr)
	refClass := webauthnhttpClass(refErr)

	resolve := map[string]func() (*webauthn.Service, error){
		"system":     func() (*webauthn.Service, error) { return f.router.For(ctx, "system") },
		"unknown":    func() (*webauthn.Service, error) { return f.router.For(ctx, "tenant-x") },
		"other-host": func() (*webauthn.Service, error) { return f.router.ForRequest(ctx, tenantLoginHostB, "system") },
	}
	for name, get := range resolve {
		for _, kind := range []loginKind{loginByEmail, loginByHandle, loginDiscoverable} {
			svc, err := get()
			require.NoError(t, err, name)
			opts, sessionID := f.begin(t, svc, kind, tenantLoginEmail)
			if kind != loginDiscoverable {
				require.Equal(t, realKeys, optionKeys(t, opts), "%s kind %d", name, kind)
				require.NotEmpty(t, opts.Response.AllowedCredentials, "%s kind %d", name, kind)
			}
			_, err = f.finish(t, svc, opts, sessionID)
			require.Error(t, err, "%s kind %d", name, kind)
			require.Equal(t, refClass, webauthnhttpClass(err), "%s kind %d: %v", name, kind, err)
		}
	}
	require.Equal(t, 1, f.router.CachedTenants())
}

func newTenantLoginDAOFactory() *qrdbsdk.DAOFactory {
	kv := qrdbsdk.NewMemoryKVStore()
	return qrdbsdk.NewDAOFactory(func(uint64) qrdbsdk.KVStore { return kv })
}

// webauthnhttpClass is the client-visible class of a finish failure.
func webauthnhttpClass(err error) string {
	if webauthn.IsVerificationFailed(err) {
		return "verification"
	}
	return err.Error()
}
