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
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// statErrorFS is a filesystem where Open succeeds but Stat on the returned file fails.
type statErrorFS struct {
	files map[string][]byte
}

func (sfs *statErrorFS) Open(name string) (http.File, error) {
	// Normalize the path by stripping leading slashes, matching real SPA usage.
	clean := strings.TrimPrefix(name, "/")
	data, ok := sfs.files[clean]
	if !ok {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
	return &statErrorFile{data: data}, nil
}

// statErrorFile is an http.File where Stat always returns an error.
type statErrorFile struct {
	data   []byte
	offset int
}

func (f *statErrorFile) Read(p []byte) (int, error) {
	n := copy(p, f.data[f.offset:])
	f.offset += n
	return n, nil
}

func (f *statErrorFile) Close() error                       { return nil }
func (f *statErrorFile) Readdir(int) ([]fs.FileInfo, error) { return nil, nil }
func (f *statErrorFile) Seek(int64, int) (int64, error)     { return 0, nil }
func (f *statErrorFile) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat failed")
}

// TestServeHTTP_StatError verifies that ServeHTTP returns a 500 error when
// Stat fails on an opened file.
func TestServeHTTP_StatError(t *testing.T) {
	handler := &spaFileServer{
		fs: &statErrorFS{
			files: map[string][]byte{
				"test.html": []byte("<html>test</html>"),
			},
		},
		logger: slog.Default(),
	}

	req := httptest.NewRequest(http.MethodGet, "/test.html", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for stat error, got %d", rec.Code)
	}
}

// dirStatErrorFS is a filesystem where opening a path returns a directory
// but that directory's index.html stat fails.
type dirStatErrorFS struct{}

func (dfs *dirStatErrorFS) Open(name string) (http.File, error) {
	clean := strings.TrimPrefix(name, "/")
	switch clean {
	case "subdir":
		return &dirFile{name: "subdir"}, nil
	case "subdir/index.html":
		return &statErrorFile{data: []byte("<html>sub</html>")}, nil
	case "index.html":
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	default:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
}

// dirFile is an http.File that reports itself as a directory.
type dirFile struct {
	name string
}

func (f *dirFile) Read([]byte) (int, error)           { return 0, nil }
func (f *dirFile) Close() error                       { return nil }
func (f *dirFile) Readdir(int) ([]fs.FileInfo, error) { return nil, nil }
func (f *dirFile) Seek(int64, int) (int64, error)     { return 0, nil }
func (f *dirFile) Stat() (fs.FileInfo, error) {
	return &dirFileInfo{name: f.name}, nil
}

type dirFileInfo struct {
	name string
}

func (fi *dirFileInfo) Name() string       { return fi.name }
func (fi *dirFileInfo) Size() int64        { return 0 }
func (fi *dirFileInfo) Mode() fs.FileMode  { return fs.ModeDir | 0755 }
func (fi *dirFileInfo) ModTime() time.Time { return time.Now() }
func (fi *dirFileInfo) IsDir() bool        { return true }
func (fi *dirFileInfo) Sys() any           { return nil }

// TestServeHTTP_DirectoryIndexStatError verifies that ServeHTTP returns a 500
// when a directory has an index.html but Stat on it fails.
func TestServeHTTP_DirectoryIndexStatError(t *testing.T) {
	handler := &spaFileServer{
		fs:     &dirStatErrorFS{},
		logger: slog.Default(),
	}

	req := httptest.NewRequest(http.MethodGet, "/subdir", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for directory index stat error, got %d", rec.Code)
	}
}

// indexStatErrorFS returns a valid filesystem except index.html stat fails.
type indexStatErrorFS struct{}

func (ifs *indexStatErrorFS) Open(name string) (http.File, error) {
	clean := strings.TrimPrefix(name, "/")
	switch clean {
	case "index.html":
		return &statErrorFile{data: []byte("<html>index</html>")}, nil
	default:
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
}

// TestServeIndex_StatError verifies that serveIndex returns a 500 when
// Stat on index.html fails.
func TestServeIndex_StatError(t *testing.T) {
	handler := &spaFileServer{
		fs:     &indexStatErrorFS{},
		logger: slog.Default(),
	}

	req := httptest.NewRequest(http.MethodGet, "/nonexistent-route", nil)
	rec := httptest.NewRecorder()

	// ServeHTTP will try to open the path, fail (not found), then call serveIndex
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for serveIndex stat error, got %d", rec.Code)
	}
}

// unreadableFS serves an index.html whose Read always fails, exercising the
// read-error branch of the injection path.
type unreadableFS struct{}

func (unreadableFS) Open(name string) (http.File, error) {
	if strings.TrimPrefix(name, "/") != "index.html" {
		return nil, fs.ErrNotExist
	}
	return &unreadableFile{}, nil
}

type unreadableFile struct{}

func (*unreadableFile) Close() error                       { return nil }
func (*unreadableFile) Read([]byte) (int, error)           { return 0, fs.ErrClosed }
func (*unreadableFile) Seek(int64, int) (int64, error)     { return 0, nil }
func (*unreadableFile) Readdir(int) ([]fs.FileInfo, error) { return nil, fs.ErrNotExist }
func (f *unreadableFile) Stat() (fs.FileInfo, error)       { return stubFileInfo{}, nil }

type stubFileInfo struct{}

func (stubFileInfo) Name() string       { return "index.html" }
func (stubFileInfo) Size() int64        { return 0 }
func (stubFileInfo) Mode() fs.FileMode  { return 0o644 }
func (stubFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (stubFileInfo) IsDir() bool        { return false }
func (stubFileInfo) Sys() any           { return nil }

// TestServeIndex_ReadFailureIs500 covers the io.ReadAll error branch reached
// only when injection is enabled. A read failure must surface as a 500, not as
// a 200 with a truncated shell that would render a blank admin console.
func TestServeIndex_ReadFailureIs500(t *testing.T) {
	handler := &spaFileServer{
		fs:         unreadableFS{},
		logger:     slog.Default(),
		apiBaseURL: "/api/v1",
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "__API_BASE_URL__") {
		t.Error("a partial injection was written despite the read failure")
	}
}

// closeErrorFile serves real content successfully (via a real bytes.Reader,
// so http.ServeContent's Seek-to-measure-length dance works exactly as it
// does for a real file) but fails on Close, exercising go-xkms#876's "log,
// don't fail" close contract: the response has already been written by the
// time Close runs, so a Close failure must be logged, never surfaced to the
// client.
type closeErrorFile struct {
	*bytes.Reader
}

func (f *closeErrorFile) Close() error                       { return errors.New("simulated close failure") }
func (f *closeErrorFile) Readdir(int) ([]fs.FileInfo, error) { return nil, nil }
func (f *closeErrorFile) Stat() (fs.FileInfo, error)         { return closeErrorFileInfo{size: f.Size()}, nil }

type closeErrorFileInfo struct{ size int64 }

func (fi closeErrorFileInfo) Name() string       { return "asset.txt" }
func (fi closeErrorFileInfo) Size() int64        { return fi.size }
func (fi closeErrorFileInfo) Mode() fs.FileMode  { return 0o644 }
func (fi closeErrorFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (fi closeErrorFileInfo) IsDir() bool        { return false }
func (fi closeErrorFileInfo) Sys() any           { return nil }

// closeErrorFS serves closeErrorFile for every path.
type closeErrorFS struct{}

func (closeErrorFS) Open(string) (http.File, error) {
	return &closeErrorFile{Reader: bytes.NewReader([]byte("ok"))}, nil
}

// recordingHandler is a minimal slog.Handler that records every record
// passed to Handle, so a test can assert a specific message/level was
// logged without parsing formatted output.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) hasRecordContaining(level slog.Level, substr string) bool {
	for _, r := range h.records {
		if r.Level == level && strings.Contains(r.Message, substr) {
			return true
		}
	}
	return false
}

// TestServeHTTP_CloseFailure_LoggedNotFatal proves a static asset's Close
// failure is logged at debug and does not affect the already-served
// response (go-xkms#876).
func TestServeHTTP_CloseFailure_LoggedNotFatal(t *testing.T) {
	handler := &recordingHandler{}
	sfs := &spaFileServer{fs: closeErrorFS{}, logger: slog.New(handler)}

	rec := httptest.NewRecorder()
	sfs.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/asset.txt", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 despite the close failure", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "ok")
	}
	if !handler.hasRecordContaining(slog.LevelDebug, "failed to close static asset file") {
		t.Fatal("expected a debug log recording the close failure")
	}
}
