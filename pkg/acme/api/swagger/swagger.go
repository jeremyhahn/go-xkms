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

// Package swagger provides Swagger UI integration for API documentation.
package swagger

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
)

//go:embed openapi/*.yaml
var openAPISpecs embed.FS

// Config contains configuration for the Swagger UI handler.
type Config struct {
	// BasePath is the base URL path for Swagger UI (default: "/docs")
	BasePath string

	// Title is the page title
	Title string

	// Logger for logging requests
	Logger *slog.Logger

	// DefaultSpec is the default spec to show (acme-api or admin-api)
	DefaultSpec string
}

// Handler provides HTTP handlers for Swagger UI and OpenAPI specs.
type Handler struct {
	basePath    string
	title       string
	logger      *slog.Logger
	defaultSpec string
}

// NewHandler creates a new Swagger UI handler.
func NewHandler(cfg *Config) *Handler {
	basePath := "/docs"
	if cfg != nil && cfg.BasePath != "" {
		basePath = cfg.BasePath
	}

	title := "go-xkms API Documentation"
	if cfg != nil && cfg.Title != "" {
		title = cfg.Title
	}

	defaultSpec := "acme-api"
	if cfg != nil && cfg.DefaultSpec != "" {
		defaultSpec = cfg.DefaultSpec
	}

	var logger *slog.Logger
	if cfg != nil && cfg.Logger != nil {
		logger = cfg.Logger
	}

	return &Handler{
		basePath:    basePath,
		title:       title,
		logger:      logger,
		defaultSpec: defaultSpec,
	}
}

// RegisterRoutes registers Swagger UI routes on the given router.
// It expects a router that supports HandleFunc(path, handler).Methods(...).
type Router interface {
	HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) routeHandler
}

type routeHandler interface {
	Methods(methods ...string) routeHandler
}

// RegisterMux registers routes on a http.ServeMux.
func (h *Handler) RegisterMux(mux *http.ServeMux) {
	mux.HandleFunc(h.basePath, h.SwaggerUIHandler)
	mux.HandleFunc(h.basePath+"/", h.SwaggerUIHandler)
	mux.HandleFunc("/openapi/", h.OpenAPISpecHandler)
}

// SwaggerUIHandler serves the Swagger UI page.
func (h *Handler) SwaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	if h.logger != nil {
		h.logger.Debug("serving swagger UI", slog.String("path", r.URL.Path))
	}

	// Determine which spec to show based on query parameter
	spec := r.URL.Query().Get("spec")
	if spec == "" {
		spec = h.defaultSpec
	}

	specURL := "/openapi/" + spec + ".yaml"

	data := struct {
		Title        string
		SpecURL      string
		ACMESpecURL  string
		AdminSpecURL string
		CurrentSpec  string
	}{
		Title:        h.title,
		SpecURL:      specURL,
		ACMESpecURL:  "/openapi/acme-api.yaml",
		AdminSpecURL: "/openapi/admin-api.yaml",
		CurrentSpec:  spec,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := swaggerUITemplate.Execute(w, data); err != nil {
		if h.logger != nil {
			h.logger.Error("failed to render swagger UI", slog.String("error", err.Error()))
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// OpenAPISpecHandler serves OpenAPI specification files.
func (h *Handler) OpenAPISpecHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the spec name from path: /openapi/{spec}.yaml
	specName := filepath.Base(r.URL.Path)
	if h.logger != nil {
		h.logger.Debug("serving openapi spec", slog.String("spec", specName))
	}

	// Read from embedded specs
	specPath := "openapi/" + specName
	content, err := fs.ReadFile(openAPISpecs, specPath)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("openapi spec not found", slog.String("spec", specName))
		}
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(content)
}

// swaggerUITemplate is the HTML template for Swagger UI.
var swaggerUITemplate = template.Must(template.New("swagger").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        html { box-sizing: border-box; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
        .topbar { background-color: #1e3a5f; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; }
        .topbar h1 { color: white; margin: 0; font-size: 20px; font-family: sans-serif; }
        .topbar .spec-selector { display: flex; gap: 10px; }
        .topbar a {
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 4px;
            font-family: sans-serif;
            font-size: 14px;
            transition: background-color 0.2s;
        }
        .topbar a:hover { background-color: rgba(255,255,255,0.1); }
        .topbar a.active { background-color: #3498db; }
        .swagger-ui .topbar { display: none; }
    </style>
</head>
<body>
    <div class="topbar">
        <h1>{{.Title}}</h1>
        <div class="spec-selector">
            <a href="?spec=acme-api" class="{{if eq .CurrentSpec "acme-api"}}active{{end}}">ACME API</a>
            <a href="?spec=admin-api" class="{{if eq .CurrentSpec "admin-api"}}active{{end}}">Admin API</a>
        </div>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: "{{.SpecURL}}",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                persistAuthorization: true,
                displayRequestDuration: true,
                filter: true,
                showExtensions: true,
                showCommonExtensions: true,
                syntaxHighlight: {
                    activate: true,
                    theme: "nord"
                }
            });
            window.ui = ui;
        };
    </script>
</body>
</html>`))
