// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package webui

import (
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// DefaultPathPrefix is the mount prefix used when the caller supplies none.
const DefaultPathPrefix = "/ui/"

// Option configures optional SPA serving behavior.
type Option func(*spaFileServer)

// WithAPIBaseURL injects a script tag into index.html that sets
// window.__API_BASE_URL__ so the frontend can discover the API prefix.
func WithAPIBaseURL(baseURL string) Option {
	return func(s *spaFileServer) {
		s.apiBaseURL = baseURL
	}
}

// NewHandler returns an http.Handler serving the SPA whose compiled assets
// live at the root of the given filesystem (the vite dist output). Static
// files are served with correct content types, directories never produce
// listings, and any path that does not resolve to a file falls back to
// index.html for client-side routing.
func NewHandler(assets fs.FS, logger *slog.Logger, opts ...Option) (http.Handler, error) {
	if assets == nil {
		return nil, &ErrNilAssets{}
	}
	if logger == nil {
		logger = slog.Default()
	}

	handler := &spaFileServer{
		fs:     http.FS(assets),
		logger: logger,
	}
	for _, opt := range opts {
		opt(handler)
	}
	return handler, nil
}

// NormalizePrefix validates and canonicalizes an SPA mount prefix: an empty
// prefix selects DefaultPathPrefix, a leading slash is required, and a
// trailing slash is appended when missing.
func NormalizePrefix(prefix string) (string, error) {
	if prefix == "" {
		return DefaultPathPrefix, nil
	}
	if !strings.HasPrefix(prefix, "/") {
		return "", &ErrInvalidPrefix{Prefix: prefix}
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix, nil
}

// MountChi mounts the SPA on a chi router under the given prefix (default
// "/ui/"). Every path below the prefix routes to the SPA handler with the
// prefix stripped, and a request for the bare prefix without its trailing
// slash redirects to the canonical prefix so relative asset URLs resolve.
func MountChi(r chi.Router, assets fs.FS, prefix string, logger *slog.Logger, opts ...Option) error {
	if r == nil {
		return &ErrNilRouter{}
	}
	normalized, err := NormalizePrefix(prefix)
	if err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}

	handler, err := NewHandler(assets, logger, opts...)
	if err != nil {
		return err
	}

	trimmed := strings.TrimSuffix(normalized, "/")
	r.Handle(normalized+"*", http.StripPrefix(trimmed, handler))
	if trimmed != "" {
		r.Get(trimmed, func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, normalized, http.StatusFound)
		})
	}

	logger.Info("mounted SPA web UI", slog.String("prefix", normalized))
	return nil
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
		injection := "<script>window.__API_BASE_URL__=" + jsStringLiteral(s.apiBaseURL) + ";</script>"
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

// jsStringLiteral renders value as a JavaScript string literal that cannot
// break out of the script it is embedded in. JSON encoding escapes quotes,
// backslashes and control characters, and Go's encoder also escapes <, > and &
// as \u003c, \u003e and \u0026, so "</script>" inside the value never closes
// the injected tag. The value is operator configuration (the advertised API
// base URL), not user input, but it is still rendered into every viewer's page.
func jsStringLiteral(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		// A string never fails to encode; keep the page safe if it ever does.
		return `""`
	}
	return string(encoded)
}
