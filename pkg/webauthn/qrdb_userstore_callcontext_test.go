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

// boundKey marks a context the store's CallContext derived, standing in
// for the identity node.ServiceContext attaches.
type boundKey struct{}

// errUnboundCall is what boundUserClient answers a call that carries no
// bound identity, as go-qrdb's authorization answers a public request's
// call (main run 74687).
var errUnboundCall = errors.New("qrdb/auth: unauthenticated: no valid credentials provided")

// errBindFailed is the binder failure the store must surface typed.
var errBindFailed = errors.New("service principal unavailable")

// boundUserClient is the in-memory user client that refuses every call
// made on a context the store's CallContext did not derive.
type boundUserClient struct {
	*fakeUserClient
}

func refuseUnbound(ctx context.Context) error {
	if ctx.Value(boundKey{}) == nil {
		return errUnboundCall
	}
	return nil
}

func (b *boundUserClient) CreateUser(ctx context.Context, req *qrdbtransport.CreateUserRequest) (*qrdbtransport.User, error) {
	if err := refuseUnbound(ctx); err != nil {
		return nil, err
	}
	return b.fakeUserClient.CreateUser(ctx, req)
}

func (b *boundUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	if err := refuseUnbound(ctx); err != nil {
		return nil, err
	}
	return b.fakeUserClient.GetUser(ctx, id)
}

func (b *boundUserClient) GetUserByEmail(ctx context.Context, tenantID, email string) (*qrdbtransport.User, error) {
	if err := refuseUnbound(ctx); err != nil {
		return nil, err
	}
	return b.fakeUserClient.GetUserByEmail(ctx, tenantID, email)
}

func (b *boundUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	if err := refuseUnbound(ctx); err != nil {
		return nil, err
	}
	return b.fakeUserClient.UpdateUser(ctx, req)
}

func (b *boundUserClient) DeleteUser(ctx context.Context, id uint64) error {
	if err := refuseUnbound(ctx); err != nil {
		return err
	}
	return b.fakeUserClient.DeleteUser(ctx, id)
}

func bindForTest(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, boundKey{}, true), nil
}

func newBoundUserStore(t *testing.T, bind func(context.Context) (context.Context, error)) UserStore {
	t.Helper()
	return newBoundUserStoreOn(t, &boundUserClient{fakeUserClient: newFakeUserClient()}, bind)
}

func newBoundUserStoreOn(t *testing.T, users *boundUserClient, bind func(context.Context) (context.Context, error)) UserStore {
	t.Helper()
	us, _, err := NewQRDBUserStoreAdapter(QRDBUserStoreOptions{
		Users:       users,
		DAOFactory:  newTestDAOFactory(),
		TenantID:    "system",
		CallContext: bind,
	})
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	return us
}

// TestQRDBUserStore_CallContextBindsEveryUserCall is the regression for
// main run 74687: a public registration ceremony's user-record calls
// carry no identity, so each must run on the context CallContext derives.
func TestQRDBUserStore_CallContextBindsEveryUserCall(t *testing.T) {
	us := newBoundUserStore(t, bindForTest)
	ctx := context.Background()

	if _, err := us.GetByEmail(ctx, "new@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetByEmail before registration: want ErrUserNotFound, got %v", err)
	}
	user, err := us.Create(ctx, "new@example.com", "New")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := us.GetByID(ctx, user.WebAuthnID()); err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if _, err := us.GetByEmail(ctx, "new@example.com"); err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if err := us.Save(ctx, user); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := us.Delete(ctx, user.WebAuthnID()); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestQRDBUserStore_NoCallContextIsRefused shows the refusing client is a
// real seam: without a binder, the ceremony's first user lookup fails the
// way main run 74687 did.
func TestQRDBUserStore_NoCallContextIsRefused(t *testing.T) {
	us := newBoundUserStore(t, nil)

	_, err := us.GetByEmail(context.Background(), "new@example.com")
	if !errors.Is(err, errUnboundCall) {
		t.Fatalf("GetByEmail without a binder: want the unauthenticated refusal, got %v", err)
	}
	if _, err := us.Create(context.Background(), "new@example.com", "New"); !errors.Is(err, errUnboundCall) {
		t.Fatalf("Create without a binder: want the unauthenticated refusal, got %v", err)
	}
}

// TestQRDBUserStore_CallContextErrorIsTyped checks a binder failure stops
// every call before the user client and surfaces as QRDBCallContextError.
func TestQRDBUserStore_CallContextErrorIsTyped(t *testing.T) {
	users := &boundUserClient{fakeUserClient: newFakeUserClient()}
	ctx := context.Background()
	user, err := newBoundUserStoreOn(t, users, bindForTest).Create(ctx, "old@example.com", "Old")
	if err != nil {
		t.Fatalf("Create on the bound store: %v", err)
	}
	us := newBoundUserStoreOn(t, users, func(context.Context) (context.Context, error) {
		return nil, errBindFailed
	})
	id := user.WebAuthnID()

	calls := map[string]func() error{
		"GetByID": func() error {
			_, err := us.GetByID(ctx, id)
			return err
		},
		"GetByEmail": func() error {
			_, err := us.GetByEmail(ctx, "new@example.com")
			return err
		},
		"Create": func() error {
			_, err := us.Create(ctx, "new@example.com", "New")
			return err
		},
		"Save":   func() error { return us.Save(ctx, user) },
		"Delete": func() error { return us.Delete(ctx, id) },
	}
	for name, call := range calls {
		err := call()
		var bindErr *QRDBCallContextError
		if !errors.As(err, &bindErr) {
			t.Fatalf("%s: want *QRDBCallContextError, got %T %v", name, err, err)
		}
		if !errors.Is(err, errBindFailed) {
			t.Fatalf("%s: the error must wrap the binder's, got %v", name, err)
		}
	}
}
