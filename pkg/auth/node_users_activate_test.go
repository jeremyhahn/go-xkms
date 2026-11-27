// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package auth_test

import (
	"context"
	"errors"
	"testing"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// guardedUsers is a node user service holding one account. Its UpdateUser
// consults the request's Guard against the committed record before it
// writes, as qrdb's conditional commit does. The embedded UserServicer is
// nil: any other method panics.
type guardedUsers struct {
	qrdbsdk.UserServicer
	account qrdbsdk.User
}

func (g *guardedUsers) UpdateUser(_ context.Context, req *qrdbsdk.UpdateUserRequest) (*qrdbsdk.User, error) {
	next := g.account
	if req.Lifecycle != "" {
		next.Lifecycle = req.Lifecycle
	}
	if req.Guard != nil {
		prior := g.account
		if err := req.Guard(&prior, &next); err != nil {
			return nil, err
		}
	}
	g.account = next
	out := g.account
	return &out, nil
}

// certActivatingUsers adds qrdb's conditional first-credential activation.
type certActivatingUsers struct {
	*guardedUsers
	bound string
}

func (c *certActivatingUsers) ActivateWithCertBinding(_ context.Context, userID uint64, thumbprint string, _ int64) (*qrdbsdk.User, error) {
	if c.account.ID != userID || c.account.Lifecycle != qrdbsdk.LifecyclePending || c.bound != "" {
		return nil, &qrdbuser.AccountNotPendingError{ID: userID, Lifecycle: c.account.Lifecycle}
	}
	c.bound = thumbprint
	c.account.Lifecycle = qrdbsdk.LifecycleActive
	out := c.account
	return &out, nil
}

type fixedSource struct{ users qrdbsdk.UserServicer }

func (s fixedSource) UserService() qrdbsdk.UserServicer { return s.users }

// TestNodeUserClient_ActivatePendingUserIsGuarded: the activation commits
// only over a pending account; an account disabled before the write is
// refused with *AccountNotPendingError and stays disabled.
func TestNodeUserClient_ActivatePendingUserIsGuarded(t *testing.T) {
	ctx := context.Background()

	pending := &guardedUsers{account: qrdbsdk.User{ID: 7, Lifecycle: qrdbsdk.LifecyclePending}}
	u, err := auth.NewNodeUserClient(fixedSource{users: pending}).ActivatePendingUser(ctx, "tenant-a", 7)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), u.Lifecycle)

	disabled := &guardedUsers{account: qrdbsdk.User{ID: 7, Lifecycle: qrdbsdk.LifecycleDisabled}}
	_, err = auth.NewNodeUserClient(fixedSource{users: disabled}).ActivatePendingUser(ctx, "tenant-a", 7)
	var notPending *qrdbuser.AccountNotPendingError
	require.True(t, errors.As(err, &notPending), "want *AccountNotPendingError, got %v", err)
	assert.Equal(t, qrdbsdk.LifecycleDisabled, disabled.account.Lifecycle)
}

// TestNodeUserClient_ActivateWithCertBinding: the call reaches the node's
// CertActivator, and a node without one fails closed with nothing written.
func TestNodeUserClient_ActivateWithCertBinding(t *testing.T) {
	ctx := context.Background()

	activating := &certActivatingUsers{guardedUsers: &guardedUsers{account: qrdbsdk.User{ID: 7, Lifecycle: qrdbsdk.LifecyclePending}}}
	u, err := auth.NewNodeUserClient(fixedSource{users: activating}).ActivateWithCertBinding(ctx, "tenant-a", 7, "tp", 0)
	require.NoError(t, err)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), u.Lifecycle)
	assert.Equal(t, "tp", activating.bound)

	plain := &guardedUsers{account: qrdbsdk.User{ID: 7, Lifecycle: qrdbsdk.LifecyclePending}}
	_, err = auth.NewNodeUserClient(fixedSource{users: plain}).ActivateWithCertBinding(ctx, "tenant-a", 7, "tp", 0)
	require.ErrorIs(t, err, auth.ErrNodeUsersNoCertActivator)
	require.ErrorIs(t, err, qrdbuser.ErrActivationUnsupported)
	assert.Equal(t, qrdbsdk.LifecyclePending, plain.account.Lifecycle)
}
