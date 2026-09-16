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

// Package api implements the embedded REST API for the Trusted ACME Client
// desktop GUI. It exposes ACME client service operations as JSON endpoints
// consumed by the Svelte frontend running inside the Wails webview.
//
// When an SDK workflow is available (non-nil), the Register and Revoke handlers
// route through the workflow for SDK transport benefits. All other operations
// use the service layer directly.
package api

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"

	svc "github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/guard"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/workflow"
)

// NewRouter creates a gorilla/mux router with all ACME client GUI API routes.
// The wf parameter may be nil when no SDK client is configured; handlers that
// support the workflow will fall back to the service layer automatically.
//
// The router is transport-agnostic: it is mounted in-process behind the Wails
// AssetServer by the desktop application and on a TCP listener by
// "trusted-acme-client serve". Every route runs behind the request guard built
// from opts, which by default serves same-origin callers only. A caller that
// mounts the router in-process passes WithInProcessTransport.
func NewRouter(wf workflow.Workflow, service *svc.Service, cfg *svc.Config, logger *slog.Logger, opts ...Option) *mux.Router {
	r := mux.NewRouter()
	h := newHandlers(wf, service, cfg, logger)

	r.Use(guard.New(logger, denyOrigin, opts...).Middleware)

	api := r.PathPrefix("/api/v1").Subrouter()

	// Account (legacy single-account endpoint)
	api.HandleFunc("/account/register", h.register).Methods(http.MethodPost, http.MethodOptions)

	// Accounts (multi-account endpoints)
	api.HandleFunc("/accounts", h.listAccounts).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/accounts", h.addAccount).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc("/accounts/{name}", h.getAccount).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/accounts/{name}", h.removeAccount).Methods(http.MethodDelete, http.MethodOptions)

	// Certificates (legacy action-based endpoints)
	api.HandleFunc("/certificate/request", h.requestCert).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc("/certificate/renew", h.renewCert).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc("/certificate/revoke", h.revokeCert).Methods(http.MethodPost, http.MethodOptions)

	// Certificates (multi-account resource endpoints)
	api.HandleFunc("/certificates", h.listCertificates).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/certificates/{name}", h.getCertificate).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/certificates/{name}/deploy", h.deployCertificate).Methods(http.MethodPost, http.MethodOptions)

	// Device (TPM)
	api.HandleFunc("/device/enroll", h.deviceEnroll).Methods(http.MethodPost, http.MethodOptions)
	api.HandleFunc("/device/attest", h.deviceAttest).Methods(http.MethodPost, http.MethodOptions)

	// Configuration
	api.HandleFunc("/config", h.getConfig).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/config", h.updateConfig).Methods(http.MethodPut, http.MethodOptions)

	// Renewal service
	api.HandleFunc("/renewal/status", h.renewalStatus).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/renewal/config", h.getRenewalConfig).Methods(http.MethodGet, http.MethodOptions)
	api.HandleFunc("/renewal/config", h.updateRenewalConfig).Methods(http.MethodPut, http.MethodOptions)

	return r
}
