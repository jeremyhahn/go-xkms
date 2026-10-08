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
	"errors"
	"log/slog"
	"os"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/require"
)

func initTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// recordingRBACClient implements qrdbtransport.RBACClient, records the
// resource:action pair it was asked to authorize, and allows exactly one
// configured pair. Driving a request through the real chi router with this
// client proves both that the RequirePermission decorator is attached to the
// route and that it demands the expected permission — a decorator asking for
// the wrong pair records the mismatch and is denied.
type recordingRBACClient struct {
	allowResource string
	allowAction   string

	gotResource string
	gotAction   string
}

func (c *recordingRBACClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.gotResource = resource
	c.gotAction = action
	if resource == c.allowResource && action == c.allowAction {
		return nil
	}
	return errors.New("permission denied")
}

func (c *recordingRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented")
}

func initTestBarrier(t *testing.T) *seal.Barrier {
	t.Helper()
	base := storage.NewMemory()
	barrier, err := seal.NewBarrier(initTestLogger(), base, seal.BarrierConfig{
		RootKeyPath:     "core/seal",
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	require.NoError(t, err)
	return barrier
}
