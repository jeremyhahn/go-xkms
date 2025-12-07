// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// MountChi mounts WebAuthn routes on a chi router.
//
// Example:
//
//	handler := webauthnhttp.NewHandler(svc)
//	r.Route("/api/v1/webauthn", func(r chi.Router) {
//	    webauthnhttp.MountChi(r, handler)
//	})
func MountChi(r chi.Router, h *Handler) {
	r.Post("/registration/begin", h.BeginRegistration)
	r.Post("/registration/finish", h.FinishRegistration)
	r.Get("/registration/status", h.RegistrationStatus)
	r.Post("/login/begin", h.BeginLogin)
	r.Post("/login/finish", h.FinishLogin)
}

// MuxRouter is an interface that matches *mux.Router from gorilla/mux.
// This avoids importing gorilla/mux as a direct dependency.
type MuxRouter interface {
	HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) MuxRoute
}

// MuxRoute is an interface that matches *mux.Route from gorilla/mux.
type MuxRoute interface {
	Methods(methods ...string) MuxRoute
}

// MountMux mounts WebAuthn routes on a gorilla/mux router.
//
// Example:
//
//	handler := webauthnhttp.NewHandler(svc)
//	webauthnhttp.MountMux(r.PathPrefix("/api/v1/webauthn").Subrouter(), handler)
func MountMux(r MuxRouter, h *Handler) {
	r.HandleFunc("/registration/begin", h.BeginRegistration).Methods("POST")
	r.HandleFunc("/registration/finish", h.FinishRegistration).Methods("POST")
	r.HandleFunc("/registration/status", h.RegistrationStatus).Methods("GET")
	r.HandleFunc("/login/begin", h.BeginLogin).Methods("POST")
	r.HandleFunc("/login/finish", h.FinishLogin).Methods("POST")
}

// MountStdlib mounts WebAuthn routes on a stdlib http.ServeMux.
// The prefix should not include a trailing slash.
//
// Note: For proper method routing with Go 1.22+, the mux should be configured
// to support method patterns. Otherwise, method checking is done in handlers.
//
// Example:
//
//	handler := webauthnhttp.NewHandler(svc)
//	webauthnhttp.MountStdlib(mux, "/api/v1/webauthn", handler)
func MountStdlib(mux *http.ServeMux, prefix string, h *Handler) {
	mux.HandleFunc(prefix+"/registration/begin", h.BeginRegistration)
	mux.HandleFunc(prefix+"/registration/finish", h.FinishRegistration)
	mux.HandleFunc(prefix+"/registration/status", h.RegistrationStatus)
	mux.HandleFunc(prefix+"/login/begin", h.BeginLogin)
	mux.HandleFunc(prefix+"/login/finish", h.FinishLogin)
}

// RouteEntry represents a single route with its method, path, and handler.
type RouteEntry struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// Routes returns a slice of route entries for manual mounting.
// Useful for frameworks not directly supported.
//
// Example:
//
//	handler := webauthnhttp.NewHandler(svc)
//	for _, route := range handler.Routes() {
//	    router.Add(route.Method, "/webauthn"+route.Path, route.Handler)
//	}
func (h *Handler) Routes() []RouteEntry {
	return []RouteEntry{
		{Method: "POST", Path: "/registration/begin", Handler: h.BeginRegistration},
		{Method: "POST", Path: "/registration/finish", Handler: h.FinishRegistration},
		{Method: "GET", Path: "/registration/status", Handler: h.RegistrationStatus},
		{Method: "POST", Path: "/login/begin", Handler: h.BeginLogin},
		{Method: "POST", Path: "/login/finish", Handler: h.FinishLogin},
	}
}

// HandlerFunc returns a single http.HandlerFunc that routes based on path.
// This is useful when you want a single handler for a path prefix.
//
// Note: This requires the request path to have the prefix already stripped.
//
// Example:
//
//	handler := webauthnhttp.NewHandler(svc)
//	mux.Handle("/api/v1/webauthn/", http.StripPrefix("/api/v1/webauthn", handler.HandlerFunc()))
func (h *Handler) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/registration/begin":
			h.BeginRegistration(w, r)
		case "/registration/finish":
			h.FinishRegistration(w, r)
		case "/registration/status":
			h.RegistrationStatus(w, r)
		case "/login/begin":
			h.BeginLogin(w, r)
		case "/login/finish":
			h.FinishLogin(w, r)
		default:
			http.NotFound(w, r)
		}
	}
}
