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
	"errors"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
)

// servicePrincipalKey marks a context the store's call-context binder has
// bound, the way a qrdb node's ServiceContext attaches its service principal.
type servicePrincipalKey struct{}

var errUnauthenticated = errors.New("qrdb/auth: unauthenticated: no valid credentials provided")

// principalGatedUserClient refuses every call whose context lacks the service
// principal, as an embedded qrdb node refuses an anonymous request (#2541).
type principalGatedUserClient struct {
	*fakeUserClient
}

func gate(ctx context.Context) error {
	if ctx.Value(servicePrincipalKey{}) == nil {
		return errUnauthenticated
	}
	return nil
}

func (g principalGatedUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	if err := gate(ctx); err != nil {
		return nil, err
	}
	return g.fakeUserClient.CreateUser(ctx, req)
}

func (g principalGatedUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	if err := gate(ctx); err != nil {
		return nil, err
	}
	return g.fakeUserClient.GetUser(ctx, id)
}

func (g principalGatedUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	if err := gate(ctx); err != nil {
		return nil, err
	}
	return g.fakeUserClient.GetUserByEmail(ctx, tenantID, email)
}

func (g principalGatedUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	if err := gate(ctx); err != nil {
		return nil, err
	}
	return g.fakeUserClient.UpdateUser(ctx, req)
}

func (g principalGatedUserClient) DeleteUser(ctx context.Context, id uint64) error {
	if err := gate(ctx); err != nil {
		return err
	}
	return g.fakeUserClient.DeleteUser(ctx, id)
}

func bindServicePrincipal(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, servicePrincipalKey{}, "node"), nil
}

// TestQRDBAdapter_CallContextRunsAsServicePrincipal is the #2541 cause: an
// anonymous browser registration/begin looked the user up on the request's
// context and qrdb refused it. With the binder set, the store's calls run as
// the node's service principal, as the DAOs do.
func TestQRDBAdapter_CallContextRunsAsServicePrincipal(t *testing.T) {
	gated := principalGatedUserClient{newFakeUserClient()}
	us, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: gated, DAOFactory: newTestDAOFactory(), TenantID: "system",
		CallContext: bindServicePrincipal,
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	ctx := context.Background() // an anonymous request carries no principal

	if _, err := us.GetByEmail(ctx, "anon@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByEmail = %v, want ErrUserNotFound", err)
	}
	user, err := us.Create(ctx, "anon@example.com", "Anon")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := us.GetByID(ctx, user.WebAuthnID()); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if err := us.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := us.Delete(ctx, user.WebAuthnID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestQRDBAdapter_NoCallContextKeepsCallerContext: a nil binder leaves the
// caller's context, as the DAOs do, so an anonymous call stays refused.
func TestQRDBAdapter_NoCallContextKeepsCallerContext(t *testing.T) {
	gated := principalGatedUserClient{newFakeUserClient()}
	us, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: gated, DAOFactory: newTestDAOFactory(), TenantID: "system",
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	if _, err := us.GetByEmail(context.Background(), "anon@example.com"); !errors.Is(err, errUnauthenticated) {
		t.Fatalf("GetByEmail = %v, want the unauthenticated refusal", err)
	}
}

// TestQRDBAdapter_CallContextErrorFailsTheCall: a bind error fails the call
// before it reaches the client.
func TestQRDBAdapter_CallContextErrorFailsTheCall(t *testing.T) {
	cause := errors.New("no service principal")
	us, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users: newFakeUserClient(), DAOFactory: newTestDAOFactory(), TenantID: "system",
		CallContext: func(context.Context) (context.Context, error) { return nil, cause },
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	if _, err := us.GetByEmail(context.Background(), "a@example.com"); !errors.Is(err, cause) {
		t.Fatalf("GetByEmail = %v, want the bind error", err)
	}
	if _, err := us.Create(context.Background(), "a@example.com", "A"); !errors.Is(err, cause) {
		t.Fatalf("Create = %v, want the bind error", err)
	}
}
