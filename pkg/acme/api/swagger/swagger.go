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

// Package swagger serves the ACME and Admin API OpenAPI specifications and a
// Swagger UI that renders them. Both the specifications (openapi/*.yaml) and
// the Swagger UI itself (assets/swagger-ui/) are embedded at build time: the
// handler never fetches anything from a CDN or any other external origin, and
// the CSP it sets on the UI page enforces that at the browser too.
package swagger

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	texttemplate "text/template"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-xkms/pkg/acme/admin"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

//go:embed openapi/*.yaml
var openAPISpecs embed.FS

// uiAssetsDir is the embedded-tree path of the vendored swagger-ui-dist
// release. Only the file types the UI page actually references are
// embedded; the LICENSE, NOTICE and VERSION files that sit alongside them
// for provenance are deliberately excluded so they are never served over
// HTTP.
const uiAssetsDir = "assets/swagger-ui"

//go:embed assets/swagger-ui/*.css assets/swagger-ui/*.js assets/swagger-ui/*.png
var uiAssets embed.FS

// uiAssetsFS is the vendored UI asset tree rooted at uiAssetsDir, computed
// once at package init. fs.Sub only fails here if uiAssetsDir itself is
// wrong, which is a build-time packaging defect the same way a malformed
// swaggerUITemplate would be, so it panics at init like the
// template.Must call below rather than threading an error through every
// caller of NewHandler.
var uiAssetsFS = func() fs.FS {
	sub, err := fs.Sub(uiAssets, uiAssetsDir)
	if err != nil {
		panic(&ErrAssetLoad{Detail: err.Error()})
	}
	return sub
}()

// uiFileServer serves the vendored swagger-ui-dist files (CSS, JS bundles,
// favicon) directly from the embedded tree.
var uiFileServer = http.FileServerFS(uiAssetsFS)

// contentSecurityPolicy is the CSP applied to the Swagger UI HTML page.
//
//   - script-src 'self' with no 'unsafe-inline'/'unsafe-eval': the page
//     loads only the vendored, same-origin bundle.js, standalone-preset.js
//     and swagger-initializer.js files; the page-configuration script that
//     older Swagger UI examples inline is instead served as its own file
//     (InitializerHandler) so no inline script is ever needed.
//   - style-src allows 'unsafe-inline' because swagger-ui-dist's syntax
//     highlighter sets inline style attributes for token colors; nothing
//     else in the vendored bundle requires it.
//   - connect-src 'self' scopes the "Try it out" requests the UI issues to
//     the same origin the spec was fetched from.
//   - object-src 'none', base-uri 'none' and frame-ancestors 'none' close
//     the classic plugin-injection and clickjacking vectors.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'"

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

// RegisterMux registers routes on a http.ServeMux. It serves the same
// endpoints as RegisterRoutes but without authentication or authorization,
// for callers that host Swagger UI on a mux that isn't the gated ACME admin
// router (for example, standalone tooling or tests).
func (h *Handler) RegisterMux(serveMux *http.ServeMux) {
	serveMux.HandleFunc(h.basePath, h.SwaggerUIHandler)
	serveMux.HandleFunc(h.basePath+"/swagger-initializer.js", h.InitializerHandler)
	serveMux.HandleFunc(h.basePath+"/", h.docsSubtreeHandler)
	serveMux.HandleFunc("/openapi/", h.OpenAPISpecHandler)
}

// docsSubtreeHandler dispatches every request under basePath+"/" that isn't
// the more specific swagger-initializer.js route registered ahead of it: the
// page itself for basePath+"/" exactly, and a vendored UI asset for
// everything else.
func (h *Handler) docsSubtreeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == h.basePath+"/" {
		h.SwaggerUIHandler(w, r)
		return
	}
	h.AssetHandler(w, r)
}

// RegisterRoutes registers the Swagger UI and OpenAPI spec routes on the
// ACME admin router, gated behind the same admin authentication and
// admin:capabilities grant as GET /admin/algorithms. The specs and the UI
// describe the full admin attack surface (every route, parameter and
// permission this deployment exposes), so they carry the same fail-closed
// registration this package's other admin routes use: a nil gate denies
// every request rather than serving the documentation publicly.
func (h *Handler) RegisterRoutes(router *mux.Router, authMiddleware admin.AuthHandler, gate *admin.PermissionGate) {
	docsRouter := router.PathPrefix(h.basePath).Subrouter()
	if authMiddleware != nil {
		docsRouter.Use(authMiddleware.Authenticate)
	}

	ui := gate.Wrap(auth.ResourceAdmin, auth.ActionCapabilities, h.SwaggerUIHandler)
	docsRouter.Handle("", ui).Methods(http.MethodGet)
	docsRouter.Handle("/", ui).Methods(http.MethodGet)
	docsRouter.Handle("/swagger-initializer.js",
		gate.Wrap(auth.ResourceAdmin, auth.ActionCapabilities, h.InitializerHandler)).Methods(http.MethodGet)
	docsRouter.PathPrefix("/").Handler(
		gate.Wrap(auth.ResourceAdmin, auth.ActionCapabilities, h.AssetHandler)).Methods(http.MethodGet)

	openAPIRouter := router.PathPrefix("/openapi").Subrouter()
	if authMiddleware != nil {
		openAPIRouter.Use(authMiddleware.Authenticate)
	}
	openAPIRouter.PathPrefix("/").Handler(
		gate.Wrap(auth.ResourceAdmin, auth.ActionCapabilities, h.OpenAPISpecHandler)).Methods(http.MethodGet)
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

	data := struct {
		Title        string
		BasePath     string
		ACMESpecURL  string
		AdminSpecURL string
		CurrentSpec  string
	}{
		Title:        h.title,
		BasePath:     h.basePath,
		ACMESpecURL:  "/openapi/acme-api.yaml",
		AdminSpecURL: "/openapi/admin-api.yaml",
		CurrentSpec:  spec,
	}

	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := swaggerUITemplate.Execute(w, data); err != nil {
		if h.logger != nil {
			h.logger.Error("failed to render swagger UI", slog.String("error", err.Error()))
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// InitializerHandler serves the page-configuration script that boots
// SwaggerUIBundle against the currently selected spec. It exists as its own
// file, rather than an inline <script> in the page, so contentSecurityPolicy
// can set script-src 'self' with no 'unsafe-inline'.
func (h *Handler) InitializerHandler(w http.ResponseWriter, r *http.Request) {
	spec := r.URL.Query().Get("spec")
	if spec == "" {
		spec = h.defaultSpec
	}
	// Only a spec this package embeds is served, and the URL written into
	// the script comes from specURLs, never from the request.
	specURL, ok := specURLs[spec]
	if !ok {
		if h.logger != nil {
			h.logger.Warn("swagger initializer requested unknown spec", slog.String("spec", spec))
		}
		http.NotFound(w, r)
		return
	}

	// json.Marshal HTML-escapes '<', '>' and '&' by default and produces a
	// double-quoted string whose escaping is a safe subset of JS
	// string-literal escaping, so the result can be embedded directly into
	// the script with a plain (non-escaping) text/template.
	specURLJSON, err := json.Marshal(specURL)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("failed to encode swagger initializer spec URL", slog.String("error", err.Error()))
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	if err := swaggerInitializerTemplate.Execute(w, string(specURLJSON)); err != nil {
		if h.logger != nil {
			h.logger.Error("failed to render swagger initializer", slog.String("error", err.Error()))
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// AssetHandler serves the vendored swagger-ui-dist files (CSS, JS bundles,
// favicon) from the embedded asset tree.
func (h *Handler) AssetHandler(w http.ResponseWriter, r *http.Request) {
	if h.logger != nil {
		h.logger.Debug("serving swagger UI asset", slog.String("path", r.URL.Path))
	}
	http.StripPrefix(h.basePath, uiFileServer).ServeHTTP(w, r)
}

// OpenAPISpecHandler serves OpenAPI specification files.
func (h *Handler) OpenAPISpecHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the spec name from path: /openapi/{spec}.yaml. path.Base, not
	// filepath.Base, because r.URL.Path is always '/'-separated regardless
	// of the host OS.
	specName := path.Base(r.URL.Path)
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
	// content is a build-embedded OpenAPI spec file (embed.FS), not
	// attacker-controlled, and served as application/yaml, never text/html.
	if _, err := w.Write(content); err != nil { // #nosec G705 -- embedded static YAML, non-HTML content-type
		if h.logger != nil {
			h.logger.Error("failed to write openapi spec response", slog.String("error", err.Error()))
		}
	}
}

// specURLs maps each embedded OpenAPI spec name to the URL it is served at.
var specURLs = map[string]string{
	"acme-api":  "/openapi/acme-api.yaml",
	"admin-api": "/openapi/admin-api.yaml",
}

// swaggerUITemplate is the HTML template for Swagger UI.
var swaggerUITemplate = template.Must(template.New("swagger").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <link rel="stylesheet" type="text/css" href="{{.BasePath}}/swagger-ui.css">
    <link rel="icon" type="image/png" href="{{.BasePath}}/favicon-32x32.png">
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
    <script src="{{.BasePath}}/swagger-ui-bundle.js"></script>
    <script src="{{.BasePath}}/swagger-ui-standalone-preset.js"></script>
    <script src="{{.BasePath}}/swagger-initializer.js?spec={{.CurrentSpec}}"></script>
</body>
</html>`))

// swaggerInitializerTemplate renders InitializerHandler's response. It is a
// text/template, not html/template, because the whole response is JavaScript
// rather than JavaScript embedded in an HTML document: the root value is
// already a JSON-encoded (and therefore JS-string-literal-safe) URL, and
// html/template's contextual autoescaper has no <script> tag to detect here
// and would otherwise HTML-escape it into invalid JavaScript.
var swaggerInitializerTemplate = texttemplate.Must(texttemplate.New("swagger-initializer").Parse(`window.onload = function() {
    const ui = SwaggerUIBundle({
        url: {{.}},
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
`))
