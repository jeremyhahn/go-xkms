// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	qrdbkv "github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

const ceremonyTenant = "acme"

// ceremonyUsers is a stateful routing user service: like go-qrdb's, every
// call acts on the tenant bound on ctx, and an unbound (anonymous) context is
// the system tenant. CreateUser refuses a request for another tenant.
type ceremonyUsers struct {
	qrdbsdk.UserServicer

	mu    sync.Mutex
	users map[uint64]*qrdbsdk.User
	next  uint64
}

func callerTenant(ctx context.Context) string {
	if id, ok := qrdbtenant.IDFromContext(ctx); ok && id != "" {
		return id
	}
	return "system"
}

func (c *ceremonyUsers) CreateUser(ctx context.Context, req *qrdbsdk.CreateUserRequest) (*qrdbsdk.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if req.TenantID != callerTenant(ctx) {
		return nil, errors.New("cross-tenant create denied")
	}
	c.next++
	now := time.Now()
	u := &qrdbsdk.User{
		ID: c.next, Username: req.Username, Email: req.Email, Name: req.Name,
		TenantID: req.TenantID, Lifecycle: qrdbsdk.LifecycleActive, CreatedAt: now, UpdatedAt: now,
	}
	c.users[u.ID] = u
	return u, nil
}

func (c *ceremonyUsers) get(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	u, ok := c.users[id]
	if !ok || u.TenantID != callerTenant(ctx) {
		return nil, &qrdbsdk.UserNotFoundError{ID: id}
	}
	return u, nil
}

func (c *ceremonyUsers) GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.get(ctx, id)
}

func (c *ceremonyUsers) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbsdk.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tenantID != callerTenant(ctx) {
		return nil, errors.New("cross-tenant lookup denied")
	}
	for _, u := range c.users {
		if u.TenantID == tenantID && u.Email == email {
			return u, nil
		}
	}
	return nil, &qrdbsdk.UserNotFoundError{Lookup: email}
}

func (c *ceremonyUsers) UpdateUser(ctx context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.get(ctx, req.ID)
}

type ceremonySource struct{ users *ceremonyUsers }

func (s ceremonySource) UserService() qrdbsdk.UserServicer { return s.users }

// TestNodeUserClient_NonSystemRegistrationCeremony runs a complete public
// registration (begin + finish) with the WebAuthn store configured for a
// non-system tenant over the node user client (Codex 5989079760): every
// user-store call of the ceremony must act in that tenant.
func TestNodeUserClient_NonSystemRegistrationCeremony(t *testing.T) {
	ctx := context.Background()
	users := &ceremonyUsers{users: map[uint64]*qrdbsdk.User{}}
	kv := qrdbsdk.NewMemoryKVStore()

	userStore, credStore, err := webauthn.NewQRDBUserStoreAdapter(webauthn.QRDBUserStoreOptions{
		Users:      auth.NewNodeUserClient(ceremonySource{users: users}).InTenant(ceremonyTenant),
		DAOFactory: qrdbsdk.NewDAOFactory(func(uint64) qrdbkv.KVStore { return kv }),
		TenantID:   ceremonyTenant,
	})
	require.NoError(t, err)

	open := true
	cfg := &webauthn.Config{
		RPID:                    "localhost",
		RPDisplayName:           "xkms",
		RPOrigins:               []string{"https://localhost"},
		AllowPublicRegistration: &open,
	}
	svc, err := webauthn.NewService(webauthn.ServiceParams{
		Config:          cfg,
		UserStore:       userStore,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: credStore,
	})
	require.NoError(t, err)

	options, sessionID, err := svc.BeginRegistration(ctx, "bob@acme.example", "Bob")
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	rp := virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]}
	attestation := virtualwebauthn.CreateAttestationResponse(rp, virtualwebauthn.NewAuthenticator(),
		virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *parsedOptions)
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(attestation))
	require.NoError(t, err)

	_, user, err := svc.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)
	require.NotNil(t, user)

	id, err := webauthn.UserIDFromHandle(user.WebAuthnID())
	require.NoError(t, err)
	require.Equal(t, ceremonyTenant, users.users[id].TenantID)
}
