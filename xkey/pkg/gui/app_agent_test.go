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

package gui

import (
	"context"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// agentTestListenAddress keeps test agent servers on loopback.
const agentTestListenAddress = "127.0.0.1:0"

// newAgentApp returns a NewApp-built App with its data directory open and a
// recording window in place of the Wails runtime, so emitted events are
// observable.
func newAgentApp(t *testing.T) (*App, *recordingWindow) {
	t.Helper()
	app := newWiredApp(t)
	window := &recordingWindow{}
	app.ui = window
	app.ctx = context.Background()
	t.Cleanup(func() { app.ctx = nil })

	require.NoError(t, app.InitializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	t.Cleanup(func() {
		if app.expiryChecker != nil {
			app.expiryChecker.Stop()
		}
	})
	return app, window
}

// connectAgentApp connects app to a REST xkmsd stand-in through the
// connection service, as the GUI's connect dialog does.
func connectAgentApp(t *testing.T, app *App) {
	t.Helper()
	srv := newBackendsServer(t, http.StatusOK, `{"backends":[]}`)
	app.connectionService.SetContext(context.Background())
	_, err := app.connectionService.Connect("rest", srv.Listener.Addr().String(), false, "", "")
	require.NoError(t, err)
}

func TestApp_AgentServer_NotReadyWithoutAServerConnection(t *testing.T) {
	app, _ := newAgentApp(t)

	err := app.agentService.StartServer(agentTestListenAddress)

	assert.ErrorIs(t, err, services.ErrAgentServiceNotReady,
		"agent enrollment needs the xkmsd certificate authority")
}

func TestApp_AgentServer_StartsOnceConnected(t *testing.T) {
	app, window := newAgentApp(t)
	connectAgentApp(t, app)
	t.Cleanup(func() { assert.NoError(t, app.connectionService.Disconnect()) })

	require.NoError(t, app.agentService.StartServer(agentTestListenAddress))
	t.Cleanup(func() {
		if app.agentService.GetServerStatus().Running {
			assert.NoError(t, app.agentService.StopServer())
		}
	})

	assert.True(t, app.agentService.GetServerStatus().Running)
	assert.True(t, slices.Contains(window.Events(), string(events.EventAgentServerStarted)),
		"the agent service's events reach the window")
}

func TestApp_AgentServer_DisconnectStopsIt(t *testing.T) {
	app, window := newAgentApp(t)
	connectAgentApp(t, app)
	require.NoError(t, app.agentService.StartServer(agentTestListenAddress))

	require.NoError(t, app.connectionService.Disconnect())

	assert.False(t, app.agentService.GetServerStatus().Running,
		"an agent server cannot enroll once its certificate authority is gone")
	assert.True(t, slices.Contains(window.Events(), string(events.EventAgentServerStopped)))
	assert.ErrorIs(t, app.agentService.StartServer(agentTestListenAddress), services.ErrAgentServiceNotReady)
}

func TestApp_Shutdown_StopsTheAgentServer(t *testing.T) {
	app, _ := newAgentApp(t)
	connectAgentApp(t, app)
	require.NoError(t, app.agentService.StartServer(agentTestListenAddress))

	app.shutdown(context.Background())

	assert.False(t, app.agentService.GetServerStatus().Running, "shutdown must stop the agent server")
}

func TestApp_InitializeDataDir_OpensTheCLIEnrollmentStore(t *testing.T) {
	app, _ := newAgentApp(t)

	info, err := os.Stat(agent.EnrollmentStoreDir(app.dataDir))

	require.NoError(t, err, "the GUI opens the enrollment store where the CLI keeps it")
	assert.True(t, info.IsDir())
}
