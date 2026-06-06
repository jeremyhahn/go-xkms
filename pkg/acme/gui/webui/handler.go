// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package webui

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// SPAOption configures optional SPA serving behavior.
type SPAOption func(*spaFileServer)

// WithAPIBaseURL injects a script tag into index.html that sets
// window.__API_BASE_URL__ so the frontend can discover the API prefix.
func WithAPIBaseURL(baseURL string) SPAOption {
	return func(s *spaFileServer) {
		s.apiBaseURL = baseURL
	}
}

// RegisterSPA mounts an SPA at the given pathPrefix on the router. The assets
// parameter should be the root embed.FS; RegisterSPA extracts the "dist"
// subdirectory automatically. The pathPrefix must include trailing slash
// (e.g. "/ui/client/").
func RegisterSPA(router *mux.Router, assets fs.FS, pathPrefix string, logger *slog.Logger, opts ...SPAOption) error {
	distFS, err := fs.Sub(assets, "dist")
	if err != nil {
		return &ErrAssetLoad{Detail: err.Error()}
	}

	spaHandler := &spaFileServer{
		fs:     http.FS(distFS),
		logger: logger,
	}
	for _, opt := range opts {
		opt(spaHandler)
	}

	router.PathPrefix(pathPrefix).Handler(
		http.StripPrefix(pathPrefix, spaHandler),
	)

	logger.Info("registered SPA web UI", slog.String("path", pathPrefix))
	return nil
}

// RegisterRoutes mounts the admin SPA under /ui/admin/ on the given router.
func RegisterRoutes(router *mux.Router, adminAssets fs.FS, logger *slog.Logger) error {
	return RegisterSPA(router, adminAssets, "/ui/admin/", logger)
}

// spaFileServer serves static files and falls back to index.html for SPA routing.
type spaFileServer struct {
	fs         http.FileSystem
	logger     *slog.Logger
	apiBaseURL string // injected into index.html as window.__API_BASE_URL__
}

// ServeHTTP serves the requested file or falls back to index.html for client-side routing.
func (s *spaFileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" || path == "/" {
		// Serve index.html (with optional API base URL injection).
		s.serveIndex(w, r)
		return
	}

	f, err := s.fs.Open(path)
	if err != nil {
		// File not found - serve index.html for SPA client-side routing
		s.serveIndex(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if stat.IsDir() {
		_ = f.Close()
		// Try index.html in the directory, then fall back to root index.html
		dirIndex, dirErr := s.fs.Open(path + "/index.html")
		if dirErr != nil {
			s.serveIndex(w, r)
			return
		}
		defer func() { _ = dirIndex.Close() }()

		stat, err = dirIndex.Stat()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.serveContent(w, r, stat, dirIndex)
		return
	}

	s.serveContent(w, r, stat, f)
}

// serveIndex serves the root index.html for SPA fallback routing.
// When apiBaseURL is set, it injects a script tag so the frontend can
// discover the API prefix.
func (s *spaFileServer) serveIndex(w http.ResponseWriter, r *http.Request) {
	f, err := s.fs.Open("index.html")
	if err != nil {
		http.Error(w, "index.html not found", http.StatusNotFound)
		return
	}
	defer func() { _ = f.Close() }()

	// If apiBaseURL is configured, inject it into the HTML.
	if s.apiBaseURL != "" {
		data, readErr := io.ReadAll(f)
		if readErr != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		injection := `<script>window.__API_BASE_URL__="` + s.apiBaseURL + `";</script>`
		html := strings.Replace(string(data), "</head>", injection+"</head>", 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(html))
		return
	}

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.serveContent(w, r, stat, f)
}

// serveContent writes the file content with proper content type detection.
func (s *spaFileServer) serveContent(w http.ResponseWriter, r *http.Request, stat fs.FileInfo, f http.File) {
	seeker, ok := f.(io.ReadSeeker)
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), seeker)
}
