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
// ACME Client GUI. It runs an embedded REST API server on a random available
// port and renders the Svelte frontend in a native webview window. The frontend
// communicates with the backend through REST API calls, discovered at startup
// via the GetApiBaseUrl Wails binding.
package client

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	clientapi "github.com/jeremyhahn/go-xkms/pkg/acme/gui/client/api"
	trustedca "github.com/jeremyhahn/go-xkms/sdk/go/acme"
)

// App is the Wails desktop application for the Trusted ACME Client GUI.
type App struct {
	ctx       context.Context
	config    *GUIConfig
	service   *svc.Service
	sdkClient trustedca.Client
	svcCfg    *svc.Config
	apiPort   int
	server    *http.Server
	logger    *slog.Logger
	running   atomic.Bool
}

// NewApp creates a new ACME client GUI application. The sdkClient parameter
// may be nil when no SDK transport is configured; the GUI will fall back to
// the service layer for all operations.
func NewApp(guiCfg *GUIConfig, service *svc.Service, sdkClient trustedca.Client, svcCfg *svc.Config, logger *slog.Logger) *App {
	return &App{
		config:    guiCfg,
		service:   service,
		sdkClient: sdkClient,
		svcCfg:    svcCfg,
		logger:    logger,
	}
}

// Run starts the embedded API server and launches the Wails desktop window.
// It blocks until the window is closed.
func (a *App) Run(assets fs.FS) error {
	if !a.running.CompareAndSwap(false, true) {
		return &ErrServerStart{Detail: "application already running"}
	}
	defer a.running.Store(false)

	if err := a.startAPIServer(); err != nil {
		return err
	}

	appOpts := &options.App{
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
			Assets: assets,
		},
	}

	return wails.Run(appOpts)
}

// GetApiBaseUrl is the single Wails binding exposed to the frontend.
// The Svelte app calls this once at startup to discover the embedded
// REST API endpoint.
func (a *App) GetApiBaseUrl() string {
	// The origin only: the frontend appends /api/v1 and the endpoint path.
	return fmt.Sprintf("http://localhost:%d", a.apiPort)
}

// Port returns the port the embedded API server is listening on.
func (a *App) Port() int {
	return a.apiPort
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
	if a.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			a.logger.Error("embedded API server shutdown error",
				slog.String("error", err.Error()),
			)
		}
	}
}

func (a *App) startAPIServer() error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return &ErrServerStart{Detail: "binding to port: " + err.Error()}
	}
	a.apiPort = listener.Addr().(*net.TCPAddr).Port

	// Build the SDK workflow if an SDK client is available.
	var wf trustedca.WorkflowInterface
	if a.sdkClient != nil {
		wf = a.sdkClient.Workflow()
	}

	router := clientapi.NewRouter(wf, a.service, a.svcCfg, a.logger)

	a.server = &http.Server{
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		a.logger.Info("embedded ACME client API server listening",
			slog.Int("port", a.apiPort),
		)
		if err := a.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			a.logger.Error("embedded ACME client API server error",
				slog.String("error", err.Error()),
			)
		}
	}()

	return nil
}
