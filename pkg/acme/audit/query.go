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

package audit

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// Query error types.
var (
	// ErrQueryUnavailable indicates the audit trail cannot be queried because
	// audit logging is disabled or has no log path configured.
	ErrQueryUnavailable = errors.New("audit: audit trail is not queryable")

	// ErrQueryWindowExceeded indicates the requested page lies beyond the
	// largest window the querier will scan into memory.
	ErrQueryWindowExceeded = errors.New("audit: requested page exceeds the maximum query window")

	// ErrInvalidTimeRange indicates the query's end bound precedes its start bound.
	ErrInvalidTimeRange = errors.New("audit: end of time range precedes its start")

	// ErrUnsupportedFormat indicates the configured log format cannot be read
	// back as line-delimited records.
	ErrUnsupportedFormat = errors.New("audit: only the json log format is queryable")
)

const (
	// DefaultQueryPageSize is the page size used when a query omits one.
	DefaultQueryPageSize = 25

	// MaxQueryPageSize is the largest page a single query may request.
	MaxQueryPageSize = 100

	// MaxQueryWindow bounds how many events a query may skip plus return,
	// which bounds the memory a single query can retain.
	MaxQueryWindow = 10000

	// compressedSuffix is appended by the log rotator to compressed backups.
	compressedSuffix = ".gz"

	// readBufferSize is the initial per-file read buffer.
	readBufferSize = 64 * 1024

	// cancelCheckInterval is how many lines are read between context checks.
	cancelCheckInterval = 512
)

// Query selects a filtered, paginated slice of the audit trail.
// The zero value returns the first page of the whole trail.
type Query struct {
	// Page is the 1-based page number.
	Page int

	// PerPage is the number of events per page.
	PerPage int

	// EventType restricts results to a single event type.
	EventType EventType

	// Actor restricts results to a single actor.
	Actor string

	// Resource restricts results to a single resource.
	Resource string

	// Action restricts results to a single action.
	Action string

	// Result restricts results to a single outcome.
	Result Result

	// RequestID restricts results to a single correlated request.
	RequestID string

	// Since excludes events recorded before this instant.
	Since time.Time

	// Until excludes events recorded after this instant.
	Until time.Time
}

// QueryResult is a page of audit events, most recently recorded first.
type QueryResult struct {
	// Events is the requested page of events, most recently recorded first.
	//
	// Events are ordered by their position in the trail rather than by their
	// timestamp: the trail's append order is its durable order, and paging
	// over it is what keeps pages from overlapping. The logger buffers writes,
	// so timestamps within a page are near-monotonic but not strictly sorted.
	Events []*AuditEvent

	// Total is the number of events matching the filter across the whole trail.
	Total int

	// Page is the 1-based page number these events came from.
	Page int

	// PerPage is the page size that was applied.
	PerPage int

	// Malformed counts log lines that could not be decoded or failed their
	// checksum. A non-zero value means the trail is damaged or truncated.
	Malformed int
}

// Querier reads persisted audit events.
type Querier interface {
	// Query returns a page of audit events matching q, most recently
	// recorded first.
	Query(ctx context.Context, q Query) (*QueryResult, error)
}

// FileQuerier reads the audit trail written by FileAuditLogger.
//
// Events are stored as one JSON document per line, so the trail is read by
// streaming the rotated backups oldest first, followed by the live log file.
// Only the requested page plus the events it skips are retained, which keeps
// memory bounded no matter how large the trail has grown.
type FileQuerier struct {
	logPath string
	codec   Codec
}

// Compile-time interface check.
var _ Querier = (*FileQuerier)(nil)

// NewFileQuerier creates a querier for the audit trail described by config.
// It returns ErrQueryUnavailable when audit logging is disabled, since a
// disabled audit trail has no events to report rather than zero events.
func NewFileQuerier(config *Config) (*FileQuerier, error) {
	if config == nil {
		return nil, caerrors.MalformedError("audit: config cannot be nil")
	}

	if !config.Enabled {
		return nil, ErrQueryUnavailable
	}

	if config.LogPath == "" {
		return nil, caerrors.MalformedError("audit: logPath is required to query the audit trail")
	}

	if config.Format != "" && config.Format != "json" {
		return nil, ErrUnsupportedFormat
	}

	absLogPath, err := filepath.Abs(config.LogPath)
	if err != nil {
		return nil, caerrors.InternalServerError("audit: failed to resolve absolute log path: %v", err)
	}

	return &FileQuerier{logPath: absLogPath, codec: DefaultCodec()}, nil
}

// LogPath returns the absolute path of the live audit log file.
func (f *FileQuerier) LogPath() string {
	return f.logPath
}

// Query returns a page of audit events matching q, most recently recorded first.
func (f *FileQuerier) Query(ctx context.Context, q Query) (*QueryResult, error) {
	if err := q.normalize(); err != nil {
		return nil, err
	}

	offset := (q.Page - 1) * q.PerPage
	window := newEventWindow(offset + q.PerPage)

	files, err := f.logFiles()
	if err != nil {
		return nil, err
	}

	result := &QueryResult{Page: q.Page, PerPage: q.PerPage, Events: []*AuditEvent{}}

	for _, path := range files {
		malformed, err := f.scanFile(ctx, path, func(event *AuditEvent) {
			if !q.matches(event) {
				return
			}
			result.Total++
			window.add(event)
		})
		result.Malformed += malformed
		if err != nil {
			return nil, err
		}
	}

	events := window.newestFirst()
	if offset < len(events) {
		end := offset + q.PerPage
		if end > len(events) {
			end = len(events)
		}
		result.Events = events[offset:end]
	}

	return result, nil
}

// normalize applies defaults and bounds, and rejects impossible queries.
func (q *Query) normalize() error {
	if q.Page <= 0 {
		q.Page = 1
	}

	if q.PerPage <= 0 {
		q.PerPage = DefaultQueryPageSize
	}
	if q.PerPage > MaxQueryPageSize {
		q.PerPage = MaxQueryPageSize
	}

	if !q.Since.IsZero() && !q.Until.IsZero() && q.Until.Before(q.Since) {
		return ErrInvalidTimeRange
	}

	if q.Page > MaxQueryWindow || q.Page*q.PerPage > MaxQueryWindow {
		return ErrQueryWindowExceeded
	}

	return nil
}

// matches reports whether an event satisfies every filter set on the query.
func (q *Query) matches(event *AuditEvent) bool {
	if q.EventType != "" && event.EventType != q.EventType {
		return false
	}
	if q.Actor != "" && event.Actor != q.Actor {
		return false
	}
	if q.Resource != "" && event.Resource != q.Resource {
		return false
	}
	if q.Action != "" && event.Action != q.Action {
		return false
	}
	if q.Result != "" && event.Result != q.Result {
		return false
	}
	if q.RequestID != "" && event.RequestID != q.RequestID {
		return false
	}
	if !q.Since.IsZero() && event.Timestamp.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && event.Timestamp.After(q.Until) {
		return false
	}

	return true
}

// logFiles returns every file holding part of the trail, oldest first. The
// rotated backups are named "<base>-<timestamp><ext>" by the rotator, so
// sorting them by name orders them chronologically.
func (f *FileQuerier) logFiles() ([]string, error) {
	dir := filepath.Dir(f.logPath)
	base := filepath.Base(f.logPath)
	ext := filepath.Ext(base)
	prefix := strings.TrimSuffix(base, ext) + "-"

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, caerrors.StorageFailureError("audit: failed to read log directory: %v", err)
	}

	files := make([]string, 0, len(entries)+1)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !strings.HasSuffix(name, ext) && !strings.HasSuffix(name, ext+compressedSuffix) {
			continue
		}

		files = append(files, filepath.Join(dir, name))
	}
	sort.Strings(files)

	// The live log file holds the newest events, so it is read last.
	if _, err := os.Stat(f.logPath); err == nil {
		files = append(files, f.logPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, caerrors.StorageFailureError("audit: failed to stat log file: %v", err)
	}

	return files, nil
}

// scanFile streams one log file, handing every decodable event to visit and
// returning the number of lines that could not be decoded.
func (f *FileQuerier) scanFile(ctx context.Context, path string, visit func(*AuditEvent)) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Rotation removed the file between listing and reading.
			return 0, nil
		}
		return 0, caerrors.StorageFailureError("audit: failed to open log file: %v", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			slog.Debug("audit: failed to close log file", slog.String("path", path), slog.String("error", closeErr.Error()))
		}
	}()

	var source io.Reader = file
	if strings.HasSuffix(path, compressedSuffix) {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return 0, caerrors.StorageFailureError("audit: failed to open compressed log file: %v", err)
		}
		defer func() {
			if closeErr := gz.Close(); closeErr != nil {
				slog.Debug("audit: failed to close compressed log reader", slog.String("path", path), slog.String("error", closeErr.Error()))
			}
		}()
		source = gz
	}

	reader := bufio.NewReaderSize(source, readBufferSize)
	malformed := 0
	lines := 0

	for {
		if lines%cancelCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return malformed, err
			}
		}
		lines++

		line, readErr := reader.ReadString('\n')
		if line != "" {
			event, err := f.decodeLine(line)
			switch {
			case err != nil:
				malformed++
			case event != nil:
				visit(event)
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return malformed, nil
			}
			return malformed, caerrors.StorageFailureError("audit: failed to read log file: %v", readErr)
		}
	}
}

// decodeLine decodes one log line. It returns (nil, nil) for blank padding
// lines and an error for lines that are damaged, truncated, or fail the
// checksum the rotating writer prepends.
func (f *FileQuerier) decodeLine(line string) (*AuditEvent, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, nil
	}

	// Lines written through ChecksumWriter carry a checksum prefix. A line
	// that fails verification is reported as damaged rather than served as a
	// trustworthy audit record.
	if !strings.HasPrefix(trimmed, "{") {
		content, valid, err := VerifyLogLine(trimmed)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, ErrChecksumMismatch
		}
		trimmed = content
	}

	event := &AuditEvent{}
	if err := f.codec.Unmarshal([]byte(trimmed), event); err != nil {
		return nil, caerrors.SerializationFailureError("audit: failed to decode event: %v", err)
	}

	if event.EventType == "" {
		return nil, caerrors.MalformedError("audit: log line has no event type")
	}

	return event, nil
}

// eventWindow retains the newest events seen, up to a fixed capacity, without
// holding the whole trail in memory.
type eventWindow struct {
	events []*AuditEvent
	next   int
	full   bool
}

// newEventWindow creates a window retaining at most capacity events.
func newEventWindow(capacity int) *eventWindow {
	if capacity < 0 {
		capacity = 0
	}
	return &eventWindow{events: make([]*AuditEvent, capacity)}
}

// add records an event, evicting the oldest retained event when full.
func (w *eventWindow) add(event *AuditEvent) {
	if len(w.events) == 0 {
		return
	}

	w.events[w.next] = event
	w.next++
	if w.next == len(w.events) {
		w.next = 0
		w.full = true
	}
}

// newestFirst returns the retained events in reverse write order, newest
// first. Write order is the audit trail's durable order, so paging over it
// yields pages that neither overlap nor skip events.
func (w *eventWindow) newestFirst() []*AuditEvent {
	size := w.next
	if w.full {
		size = len(w.events)
	}

	ordered := make([]*AuditEvent, 0, size)
	for i := 0; i < size; i++ {
		// Walk backwards from the most recently added slot.
		index := (w.next - 1 - i + len(w.events)) % len(w.events)
		ordered = append(ordered, w.events[index])
	}

	return ordered
}
