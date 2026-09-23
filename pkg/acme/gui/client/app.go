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

//go:build gui

// Package client implements the Wails v2 desktop application for the Trusted
// ACME Client GUI. The REST API is mounted in-process as the Wails AssetServer
// Handler, alongside the Svelte frontend it serves, so the application opens no
// network listener at all: the webview reaches every route same-origin through
// fetch("/api/v1/..."), and no other process on the machine can reach any of
// them.
package client

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	clientapi "github.com/jeremyhahn/go-xkms/pkg/acme/gui/client/api"
	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// sameOriginAPIBase is the API base URL handed to the frontend. The API shares
// the webview's origin, so the base is empty and every path the frontend
// builds ("/api/v1/...") is relative to the window's own origin.
const sameOriginAPIBase = ""

// App is the Wails desktop application for the Trusted ACME Client GUI.
type App struct {
	ctx       context.Context
	config    *GUIConfig
	service   *svc.Service
	sdkClient trustedca.Client
	logger    *slog.Logger
	running   atomic.Bool
}

// NewApp creates a new ACME client GUI application. The sdkClient parameter
// may be nil when no SDK transport is configured; the GUI will fall back to
// the service layer for all operations.
func NewApp(guiCfg *GUIConfig, service *svc.Service, sdkClient trustedca.Client, logger *slog.Logger) *App {
	return &App{
		config:    guiCfg,
		service:   service,
		sdkClient: sdkClient,
		logger:    logger,
	}
}

// Run launches the Wails desktop window. It blocks until the window is closed.
func (a *App) Run(assets fs.FS) error {
	if !a.running.CompareAndSwap(false, true) {
		return &ErrServerStart{Detail: "application already running"}
	}
	defer a.running.Store(false)

	return wails.Run(a.wailsOptions(assets))
}

// wailsOptions builds the Wails application options, including the AssetServer
// that serves the frontend and the REST API from the same origin.
func (a *App) wailsOptions(assets fs.FS) *options.App {
	return &options.App{
		Title:         a.config.Title,
		Width:         a.config.Width,
		Height:        a.config.Height,
		MinWidth:      a.config.MinWidth,
		MinHeight:     a.config.MinHeight,
		DisableResize: false,
		Frameless:     false,
		OnStartup:     a.startup,
		OnShutdown:    a.shutdown,
		Bind:          []interface{}{a},
		Linux: &linux.Options{
			ProgramName: "trusted-acme-client",
		},
		AssetServer: &assetserver.Options{
			// A GET request is served from Assets first and falls back to
			// Handler when the file does not exist; every non-GET request goes
			// straight to Handler. So the SPA keeps loading from Assets and
			// /api/v1 lands on the router, with no listener under either.
			Assets:  assets,
			Handler: a.apiHandler(),
		},
	}
}

// apiHandler builds the REST API the webview calls. It is reachable only
// through the AssetServer, in-process, which is why the router is built for
// the in-process transport.
func (a *App) apiHandler() http.Handler {
	var wf trustedca.WorkflowInterface
	if a.sdkClient != nil {
		wf = a.sdkClient.Workflow()
	}

	return clientapi.NewRouter(wf, a.service, a.logger,
		clientapi.WithInProcessTransport(),
	)
}

// GetApiBaseUrl is the single Wails binding exposed to the frontend. The API
// is served by the same AssetServer as the frontend itself, so the base is the
// empty string: the Svelte transport prefixes nothing and fetches
// "/api/v1/..." against the window's own origin.
func (a *App) GetApiBaseUrl() string {
	return sameOriginAPIBase
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(ctx context.Context) {
	if a.sdkClient != nil {
		if err := a.sdkClient.Close(); err != nil {
			a.logger.Error("SDK client close error",
				slog.String("error", err.Error()),
			)
		}
	}
}
