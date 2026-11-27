// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package auth_test

import (
	"context"
	"errors"
	"testing"

	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// tenantRecordingUsers records the tenant bound on each call's ctx.
type tenantRecordingUsers struct {
	qrdbsdk.UserServicer
	seen  []string
	calls int
}

func (u *tenantRecordingUsers) record(ctx context.Context) {
	u.calls++
	id, _ := qrdbtenant.IDFromContext(ctx)
	u.seen = append(u.seen, id)
}

func (u *tenantRecordingUsers) user(id uint64) *qrdbsdk.User {
	return &qrdbsdk.User{ID: id, Lifecycle: qrdbsdk.LifecycleActive}
}

func (u *tenantRecordingUsers) GetUser(ctx context.Context, id uint64) (*qrdbsdk.User, error) {
	u.record(ctx)
	return u.user(id), nil
}

func (u *tenantRecordingUsers) UpdateUser(ctx context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error) {
	u.record(ctx)
	return u.user(req.ID), nil
}

func (u *tenantRecordingUsers) DeleteUser(ctx context.Context, _ uint64) error {
	u.record(ctx)
	return nil
}

func (u *tenantRecordingUsers) AddCertBinding(ctx context.Context, userID uint64, _ string, _ int64) (*qrdbsdk.User, error) {
	u.record(ctx)
	return u.user(userID), nil
}

func (u *tenantRecordingUsers) ActivateWithCertBinding(ctx context.Context, userID uint64, _ string, _ int64) (*qrdbsdk.User, error) {
	u.record(ctx)
	return u.user(userID), nil
}

type tenantRecordingSource struct{ users *tenantRecordingUsers }

func (s tenantRecordingSource) UserService() qrdbsdk.UserServicer { return s.users }

// byIDCalls drives every by-id method of NodeUserClient with tenantID.
func byIDCalls(c *auth.NodeUserClient) map[string]func(ctx context.Context, tenantID string) error {
	return map[string]func(ctx context.Context, tenantID string) error{
		"GetUser": func(ctx context.Context, tenantID string) error {
			_, err := c.GetUser(ctx, tenantID, 7)
			return err
		},
		"UpdateUser": func(ctx context.Context, tenantID string) error {
			_, err := c.UpdateUser(ctx, tenantID, &qrdbtransport.UpdateUserRequest{ID: 7})
			return err
		},
		"DeleteUser": func(ctx context.Context, tenantID string) error {
			return c.DeleteUser(ctx, tenantID, 7)
		},
		"AddCertBinding": func(ctx context.Context, tenantID string) error {
			_, err := c.AddCertBinding(ctx, tenantID, 7, "tp", 0)
			return err
		},
		"ActivatePendingUser": func(ctx context.Context, tenantID string) error {
			_, err := c.ActivatePendingUser(ctx, tenantID, 7)
			return err
		},
		"ActivateWithCertBinding": func(ctx context.Context, tenantID string) error {
			_, err := c.ActivateWithCertBinding(ctx, tenantID, 7, "tp", 0)
			return err
		},
	}
}

func TestNodeUserClient_ByIDMethodsBindTheGivenTenant(t *testing.T) {
	const want = "tenant-b"
	ctxs := map[string]context.Context{
		"no tenant":      context.Background(),
		"another tenant": qrdbtenant.WithTenantID(context.Background(), "tenant-a"),
	}
	for ctxName, ctx := range ctxs {
		users := &tenantRecordingUsers{}
		for name, call := range byIDCalls(auth.NewNodeUserClient(tenantRecordingSource{users: users})) {
			before := users.calls
			if err := call(ctx, want); err != nil {
				t.Fatalf("%s (%s): %v", name, ctxName, err)
			}
			if users.calls != before+1 {
				t.Fatalf("%s (%s): user service calls = %d, want %d", name, ctxName, users.calls, before+1)
			}
			if got := users.seen[len(users.seen)-1]; got != want {
				t.Errorf("%s (%s): bound tenant = %q, want %q", name, ctxName, got, want)
			}
		}
	}
}

func TestNodeUserClient_ByIDMethodsRefuseEmptyTenant(t *testing.T) {
	ctx := qrdbtenant.WithTenantID(context.Background(), "tenant-a")
	users := &tenantRecordingUsers{}
	for name, call := range byIDCalls(auth.NewNodeUserClient(tenantRecordingSource{users: users})) {
		err := call(ctx, "")
		if !errors.Is(err, auth.ErrNodeUsersNoTenant) {
			t.Errorf("%s: err = %v, want ErrNodeUsersNoTenant", name, err)
		}
	}
	if users.calls != 0 {
		t.Errorf("user service called %d times with an empty tenant, want 0", users.calls)
	}
}
