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

package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
)

// newHealthyRESTServer starts a loopback HTTP server (an OS-assigned
// ephemeral port, never a fixed one) that answers GET /health the way a
// real xkmsd REST transport does, so Connect's health-check round trip can
// be exercised without a real server.
func newHealthyRESTServer(t *testing.T, version string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","version":"` + version + `"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConnectionServiceConnect_Success(t *testing.T) {
	srv := newHealthyRESTServer(t, "test-1.2.3")

	svc := NewConnectionService()
	svc.SetContext(context.Background())

	var emitted []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emitted = append(emitted, e)
	})

	info, err := svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, "connected", info.State)
	assert.Equal(t, "rest", info.Protocol)
	assert.Equal(t, "test-1.2.3", info.Version)
	assert.False(t, info.TLS)
	assert.True(t, svc.IsConnected())
	assert.NotNil(t, svc.GetClient())

	require.Len(t, emitted, 1)
	assert.Equal(t, events.EventServerConnected, emitted[0].Type)
}

func TestConnectionServiceConnect_SuccessThenAlreadyConnected(t *testing.T) {
	srv := newHealthyRESTServer(t, "test-1.0.0")

	svc := NewConnectionService()
	svc.SetContext(context.Background())

	_, err := svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)

	_, err = svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	assert.ErrorIs(t, err, ErrServerAlreadyConnected)
}

func TestConnectionServiceHealthCheck_Success(t *testing.T) {
	srv := newHealthyRESTServer(t, "test-9.9.9")

	svc := NewConnectionService()
	svc.SetContext(context.Background())

	_, err := svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)

	resp, err := svc.HealthCheck()
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "test-9.9.9", resp.Version)
}

func TestConnectionServiceDisconnect_AfterSuccessfulConnect(t *testing.T) {
	srv := newHealthyRESTServer(t, "test-2.0.0")

	svc := NewConnectionService()
	svc.SetContext(context.Background())

	_, err := svc.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)

	require.NoError(t, svc.Disconnect())
	assert.False(t, svc.IsConnected())
	assert.Nil(t, svc.GetClient())
}
