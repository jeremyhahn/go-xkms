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
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestQuerierConfig returns an enabled audit config writing into a temp dir.
func newTestQuerierConfig(t *testing.T) *Config {
	t.Helper()

	return &Config{
		Enabled:              true,
		LogPath:              filepath.Join(t.TempDir(), "audit.log"),
		MaxSizeMB:            10,
		MaxAgeDays:           1,
		MaxBackups:           3,
		Format:               "json",
		BufferSize:           16,
		FlushIntervalSeconds: 1,
	}
}

// writeEvents appends events to a log file in the JSON-lines format the
// audit logger produces.
func writeEvents(t *testing.T, path string, events ...*AuditEvent) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		t.Fatalf("failed to create log directory: %v", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("failed to open log file: %v", err)
	}
	defer func() { _ = file.Close() }()

	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("failed to marshal event: %v", err)
		}
		if _, err := file.Write(append(data, '\n')); err != nil {
			t.Fatalf("failed to write event: %v", err)
		}
	}
}

// testEvent builds a valid audit event at the given offset from a fixed base.
func testEvent(index int, eventType EventType, actor string, result Result) *AuditEvent {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	return &AuditEvent{
		Timestamp: base.Add(time.Duration(index) * time.Minute),
		EventType: eventType,
		Actor:     actor,
		Resource:  "certificate:" + actor,
		Action:    "issue",
		Result:    result,
		RequestID: "req-" + actor,
	}
}

// TestFileQuerier_ReturnsWrittenEvents is the test the fabricated handler
// could never pass: a store that has events must report them.
func TestFileQuerier_ReturnsWrittenEvents(t *testing.T) {
	config := newTestQuerierConfig(t)

	logger, err := NewFileAuditLogger(config)
	if err != nil {
		t.Fatalf("NewFileAuditLogger() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	ctx := context.Background()
	if err := LogCertificateIssued(ctx, logger, "42", "77", "example.com", 90, "ABC123"); err != nil {
		t.Fatalf("LogCertificateIssued() error = %v", err)
	}
	if err := LogCertificateRevoked(ctx, logger, "42", "ABC123", 1); err != nil {
		t.Fatalf("LogCertificateRevoked() error = %v", err)
	}
	if err := logger.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	result, err := querier.Query(ctx, Query{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if result.Total != 2 {
		t.Fatalf("Total = %d, want 2", result.Total)
	}
	if len(result.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(result.Events))
	}
	if result.Malformed != 0 {
		t.Errorf("Malformed = %d, want 0", result.Malformed)
	}

	// Newest first.
	if result.Events[0].EventType != EventCertificateRevoked {
		t.Errorf("Events[0].EventType = %q, want %q", result.Events[0].EventType, EventCertificateRevoked)
	}
	if result.Events[1].EventType != EventCertificateIssued {
		t.Errorf("Events[1].EventType = %q, want %q", result.Events[1].EventType, EventCertificateIssued)
	}
	if got := result.Events[1].Details["common_name"]; got != "example.com" {
		t.Errorf("Details[common_name] = %v, want example.com", got)
	}
}

// TestFileQuerier_Paging verifies pages partition the trail newest first.
func TestFileQuerier_Paging(t *testing.T) {
	config := newTestQuerierConfig(t)

	events := make([]*AuditEvent, 0, 10)
	for i := 0; i < 10; i++ {
		events = append(events, testEvent(i, EventCertificateIssued, "actor", ResultSuccess))
	}
	writeEvents(t, config.LogPath, events...)

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	tests := []struct {
		name       string
		query      Query
		wantLen    int
		wantNewest time.Time
	}{
		{"first page", Query{Page: 1, PerPage: 4}, 4, events[9].Timestamp},
		{"second page", Query{Page: 2, PerPage: 4}, 4, events[5].Timestamp},
		{"last partial page", Query{Page: 3, PerPage: 4}, 2, events[1].Timestamp},
		{"page past the end", Query{Page: 4, PerPage: 4}, 0, time.Time{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := querier.Query(context.Background(), tt.query)
			if err != nil {
				t.Fatalf("Query() error = %v", err)
			}

			if result.Total != 10 {
				t.Errorf("Total = %d, want 10", result.Total)
			}
			if len(result.Events) != tt.wantLen {
				t.Fatalf("len(Events) = %d, want %d", len(result.Events), tt.wantLen)
			}
			if tt.wantLen == 0 {
				return
			}
			if !result.Events[0].Timestamp.Equal(tt.wantNewest) {
				t.Errorf("Events[0].Timestamp = %v, want %v", result.Events[0].Timestamp, tt.wantNewest)
			}

			// Every page must be ordered newest first.
			for i := 1; i < len(result.Events); i++ {
				if result.Events[i].Timestamp.After(result.Events[i-1].Timestamp) {
					t.Fatalf("events out of order at %d", i)
				}
			}
		})
	}
}

// TestFileQuerier_PagesDoNotOverlap verifies consecutive pages return disjoint
// events that together cover the whole trail.
func TestFileQuerier_PagesDoNotOverlap(t *testing.T) {
	config := newTestQuerierConfig(t)

	events := make([]*AuditEvent, 0, 7)
	for i := 0; i < 7; i++ {
		events = append(events, testEvent(i, EventOrderCreated, "actor", ResultSuccess))
	}
	writeEvents(t, config.LogPath, events...)

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	seen := make(map[time.Time]bool)
	for page := 1; page <= 3; page++ {
		result, err := querier.Query(context.Background(), Query{Page: page, PerPage: 3})
		if err != nil {
			t.Fatalf("Query(page=%d) error = %v", page, err)
		}

		for _, event := range result.Events {
			if seen[event.Timestamp] {
				t.Fatalf("event at %v returned on more than one page", event.Timestamp)
			}
			seen[event.Timestamp] = true
		}
	}

	if len(seen) != 7 {
		t.Fatalf("paged through %d events, want 7", len(seen))
	}
}

// TestFileQuerier_Filters verifies every supported filter.
func TestFileQuerier_Filters(t *testing.T) {
	config := newTestQuerierConfig(t)

	issued := testEvent(0, EventCertificateIssued, "alice", ResultSuccess)
	revoked := testEvent(1, EventCertificateRevoked, "bob", ResultSuccess)
	failed := testEvent(2, EventAuthenticationFailed, "alice", ResultFailure)
	failed.Action = "authenticate"
	writeEvents(t, config.LogPath, issued, revoked, failed)

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	tests := []struct {
		name  string
		query Query
		want  int
	}{
		{"no filter", Query{}, 3},
		{"event type", Query{EventType: EventCertificateIssued}, 1},
		{"actor", Query{Actor: "alice"}, 2},
		{"resource", Query{Resource: "certificate:bob"}, 1},
		{"action", Query{Action: "authenticate"}, 1},
		{"result failure", Query{Result: ResultFailure}, 1},
		{"result success", Query{Result: ResultSuccess}, 2},
		{"request id", Query{RequestID: "req-bob"}, 1},
		{"since", Query{Since: revoked.Timestamp}, 2},
		{"until", Query{Until: revoked.Timestamp}, 2},
		{"since and until", Query{Since: revoked.Timestamp, Until: revoked.Timestamp}, 1},
		{"combined", Query{Actor: "alice", Result: ResultFailure}, 1},
		{"no match", Query{Actor: "carol"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := querier.Query(context.Background(), tt.query)
			if err != nil {
				t.Fatalf("Query() error = %v", err)
			}

			if result.Total != tt.want {
				t.Errorf("Total = %d, want %d", result.Total, tt.want)
			}
			if len(result.Events) != tt.want {
				t.Errorf("len(Events) = %d, want %d", len(result.Events), tt.want)
			}
		})
	}
}

// TestFileQuerier_EmptyTrail verifies an empty store reports a genuine empty
// result rather than an error.
func TestFileQuerier_EmptyTrail(t *testing.T) {
	config := newTestQuerierConfig(t)

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	// No log file has been created yet.
	result, err := querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query() with no log file error = %v", err)
	}
	if result.Total != 0 || len(result.Events) != 0 {
		t.Fatalf("Total = %d, len(Events) = %d, want 0/0", result.Total, len(result.Events))
	}

	// An existing but empty log file behaves the same.
	writeEvents(t, config.LogPath)
	result, err = querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query() with empty log file error = %v", err)
	}
	if result.Total != 0 || len(result.Events) != 0 {
		t.Fatalf("Total = %d, len(Events) = %d, want 0/0", result.Total, len(result.Events))
	}
	if result.Page != 1 || result.PerPage != DefaultQueryPageSize {
		t.Errorf("Page/PerPage = %d/%d, want 1/%d", result.Page, result.PerPage, DefaultQueryPageSize)
	}
}

// TestFileQuerier_ReadsRotatedBackups verifies rotated and compressed backups
// are part of the trail.
func TestFileQuerier_ReadsRotatedBackups(t *testing.T) {
	config := newTestQuerierConfig(t)
	dir := filepath.Dir(config.LogPath)

	oldest := filepath.Join(dir, "audit-2026-01-01T00-00-00.000.log")
	writeEvents(t, oldest, testEvent(0, EventAccountCreated, "oldest", ResultSuccess))

	middle := filepath.Join(dir, "audit-2026-01-02T00-00-00.000.log")
	writeEvents(t, middle, testEvent(1, EventAccountCreated, "middle", ResultSuccess))

	// Compress the middle backup the way the rotator does.
	compressFile(t, middle)

	writeEvents(t, config.LogPath, testEvent(2, EventAccountCreated, "current", ResultSuccess))

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	result, err := querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if result.Total != 3 {
		t.Fatalf("Total = %d, want 3 (two backups plus the live file)", result.Total)
	}

	wantOrder := []string{"current", "middle", "oldest"}
	for i, actor := range wantOrder {
		if result.Events[i].Actor != actor {
			t.Errorf("Events[%d].Actor = %q, want %q", i, result.Events[i].Actor, actor)
		}
	}
}

// TestFileQuerier_IgnoresUnrelatedFiles verifies only this trail's files are read.
func TestFileQuerier_IgnoresUnrelatedFiles(t *testing.T) {
	config := newTestQuerierConfig(t)
	dir := filepath.Dir(config.LogPath)

	writeEvents(t, config.LogPath, testEvent(0, EventOrderCreated, "mine", ResultSuccess))
	writeEvents(t, filepath.Join(dir, "other-2026-01-01T00-00-00.000.log"), testEvent(1, EventOrderCreated, "theirs", ResultSuccess))
	writeEvents(t, filepath.Join(dir, "audit-2026-01-01T00-00-00.000.txt"), testEvent(2, EventOrderCreated, "wrong-ext", ResultSuccess))

	if err := os.MkdirAll(filepath.Join(dir, "audit-subdir.log"), 0750); err != nil {
		t.Fatalf("failed to create decoy directory: %v", err)
	}

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	result, err := querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if result.Total != 1 || result.Events[0].Actor != "mine" {
		t.Fatalf("Total = %d, first actor = %v, want 1 event from this trail", result.Total, result.Events)
	}
}

// TestFileQuerier_DamagedLines verifies corrupt records are counted, skipped,
// and never served as valid audit records.
func TestFileQuerier_DamagedLines(t *testing.T) {
	config := newTestQuerierConfig(t)

	valid := testEvent(0, EventCertificateIssued, "alice", ResultSuccess)
	writeEvents(t, config.LogPath, valid)

	file, err := os.OpenFile(config.LogPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("failed to reopen log: %v", err)
	}
	lines := []string{
		"",                       // blank padding
		"   ",                    // whitespace padding
		"{\"event_type\":",       // truncated JSON
		"{}",                     // JSON without an event type
		"not json at all",        // not a record
		"deadbeef {\"a\":\"b\"}", // checksum prefix that does not verify
	}
	for _, line := range lines {
		if _, err := file.WriteString(line + "\n"); err != nil {
			t.Fatalf("failed to write line: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("failed to close log: %v", err)
	}

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	result, err := querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if result.Total != 1 {
		t.Errorf("Total = %d, want 1 valid event", result.Total)
	}
	if result.Malformed != 4 {
		t.Errorf("Malformed = %d, want 4 damaged lines", result.Malformed)
	}
}

// TestFileQuerier_ChecksummedLines verifies lines carrying a valid checksum
// prefix are decoded.
func TestFileQuerier_ChecksummedLines(t *testing.T) {
	config := newTestQuerierConfig(t)

	event := testEvent(0, EventCAInitialized, "system", ResultSuccess)
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	if err := os.WriteFile(config.LogPath, []byte(FormatChecksummedLine(string(data))+"\n"), 0600); err != nil {
		t.Fatalf("failed to write checksummed line: %v", err)
	}

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	result, err := querier.Query(context.Background(), Query{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	if result.Total != 1 || result.Malformed != 0 {
		t.Fatalf("Total = %d, Malformed = %d, want 1/0", result.Total, result.Malformed)
	}
	if result.Events[0].EventType != EventCAInitialized {
		t.Errorf("EventType = %q, want %q", result.Events[0].EventType, EventCAInitialized)
	}
}

// TestNewFileQuerier_Invalid verifies unusable configurations are rejected
// with typed errors instead of producing a querier that reports nothing.
func TestNewFileQuerier_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr error
	}{
		{"nil config", nil, nil},
		{"disabled", &Config{Enabled: false, LogPath: "audit.log"}, ErrQueryUnavailable},
		{"no log path", &Config{Enabled: true}, nil},
		{"binary format", &Config{Enabled: true, LogPath: "audit.log", Format: "cbor"}, ErrUnsupportedFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			querier, err := NewFileQuerier(tt.config)
			if err == nil {
				t.Fatal("NewFileQuerier() error = nil, want an error")
			}
			if querier != nil {
				t.Error("NewFileQuerier() returned a querier alongside an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestNewFileQuerier_ResolvesAbsolutePath verifies the log path is absolute so
// the querier is independent of the process working directory.
func TestNewFileQuerier_ResolvesAbsolutePath(t *testing.T) {
	querier, err := NewFileQuerier(&Config{Enabled: true, LogPath: "relative/audit.log"})
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	if !filepath.IsAbs(querier.LogPath()) {
		t.Errorf("LogPath() = %q, want an absolute path", querier.LogPath())
	}
}

// TestQuery_Normalize verifies defaults, clamping, and rejected queries.
func TestQuery_Normalize(t *testing.T) {
	tests := []struct {
		name        string
		query       Query
		wantPage    int
		wantPerPage int
		wantErr     error
	}{
		{"defaults", Query{}, 1, DefaultQueryPageSize, nil},
		{"negative page", Query{Page: -3, PerPage: 10}, 1, 10, nil},
		{"clamped page size", Query{Page: 1, PerPage: MaxQueryPageSize + 50}, 1, MaxQueryPageSize, nil},
		{"window exceeded", Query{Page: 500, PerPage: 100}, 0, 0, ErrQueryWindowExceeded},
		{"page beyond window", Query{Page: MaxQueryWindow + 1, PerPage: 1}, 0, 0, ErrQueryWindowExceeded},
		{
			"inverted range",
			Query{
				Since: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Until: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			0, 0, ErrInvalidTimeRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := tt.query
			err := query.normalize()

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("normalize() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("normalize() error = %v", err)
			}
			if query.Page != tt.wantPage {
				t.Errorf("Page = %d, want %d", query.Page, tt.wantPage)
			}
			if query.PerPage != tt.wantPerPage {
				t.Errorf("PerPage = %d, want %d", query.PerPage, tt.wantPerPage)
			}
		})
	}
}

// TestFileQuerier_RejectsOversizedWindow verifies the query is refused rather
// than loading an unbounded slice of the trail into memory.
func TestFileQuerier_RejectsOversizedWindow(t *testing.T) {
	config := newTestQuerierConfig(t)
	writeEvents(t, config.LogPath, testEvent(0, EventOrderCreated, "actor", ResultSuccess))

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	if _, err := querier.Query(context.Background(), Query{Page: 1000, PerPage: 100}); !errors.Is(err, ErrQueryWindowExceeded) {
		t.Fatalf("Query() error = %v, want ErrQueryWindowExceeded", err)
	}
}

// TestFileQuerier_ContextCancelled verifies a cancelled context stops the scan.
func TestFileQuerier_ContextCancelled(t *testing.T) {
	config := newTestQuerierConfig(t)
	writeEvents(t, config.LogPath, testEvent(0, EventOrderCreated, "actor", ResultSuccess))

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := querier.Query(ctx, Query{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Query() error = %v, want context.Canceled", err)
	}
}

// TestFileQuerier_UnreadableDirectory verifies storage errors surface instead
// of being reported as an empty trail.
func TestFileQuerier_UnreadableDirectory(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "locked", "audit.log")

	if err := os.MkdirAll(filepath.Dir(logPath), 0750); err != nil {
		t.Fatalf("failed to create log directory: %v", err)
	}
	writeEvents(t, logPath, testEvent(0, EventOrderCreated, "actor", ResultSuccess))

	if err := os.Chmod(filepath.Dir(logPath), 0000); err != nil {
		t.Fatalf("failed to chmod log directory: %v", err)
	}
	defer func() { _ = os.Chmod(filepath.Dir(logPath), 0750) }()

	if os.Geteuid() == 0 {
		// Root ignores directory permissions; the failure path is unreachable.
		return
	}

	querier, err := NewFileQuerier(&Config{Enabled: true, LogPath: logPath, Format: "json"})
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	if _, err := querier.Query(context.Background(), Query{}); err == nil {
		t.Fatal("Query() error = nil, want a storage failure")
	}
}

// TestFileQuerier_CorruptGzip verifies a damaged compressed backup is reported.
func TestFileQuerier_CorruptGzip(t *testing.T) {
	config := newTestQuerierConfig(t)
	dir := filepath.Dir(config.LogPath)

	corrupt := filepath.Join(dir, "audit-2026-01-01T00-00-00.000.log.gz")
	if err := os.WriteFile(corrupt, []byte("this is not gzip data"), 0600); err != nil {
		t.Fatalf("failed to write corrupt backup: %v", err)
	}

	querier, err := NewFileQuerier(config)
	if err != nil {
		t.Fatalf("NewFileQuerier() error = %v", err)
	}

	if _, err := querier.Query(context.Background(), Query{}); err == nil {
		t.Fatal("Query() error = nil, want a storage failure for the corrupt backup")
	}
}

// TestEventWindow verifies the bounded retention window.
func TestEventWindow(t *testing.T) {
	t.Run("zero capacity retains nothing", func(t *testing.T) {
		window := newEventWindow(0)
		window.add(testEvent(0, EventOrderCreated, "actor", ResultSuccess))

		if got := window.newestFirst(); len(got) != 0 {
			t.Fatalf("newestFirst() returned %d events, want 0", len(got))
		}
	})

	t.Run("negative capacity is treated as zero", func(t *testing.T) {
		window := newEventWindow(-5)
		window.add(testEvent(0, EventOrderCreated, "actor", ResultSuccess))

		if got := window.newestFirst(); len(got) != 0 {
			t.Fatalf("newestFirst() returned %d events, want 0", len(got))
		}
	})

	t.Run("retains the newest events", func(t *testing.T) {
		window := newEventWindow(3)
		for i := 0; i < 10; i++ {
			window.add(testEvent(i, EventOrderCreated, "actor", ResultSuccess))
		}

		got := window.newestFirst()
		if len(got) != 3 {
			t.Fatalf("newestFirst() returned %d events, want 3", len(got))
		}

		base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i, event := range got {
			want := base.Add(time.Duration(9-i) * time.Minute)
			if !event.Timestamp.Equal(want) {
				t.Errorf("events[%d].Timestamp = %v, want %v", i, event.Timestamp, want)
			}
		}
	})

	t.Run("partially filled", func(t *testing.T) {
		window := newEventWindow(5)
		window.add(testEvent(0, EventOrderCreated, "actor", ResultSuccess))
		window.add(testEvent(1, EventOrderCreated, "actor", ResultSuccess))

		got := window.newestFirst()
		if len(got) != 2 {
			t.Fatalf("newestFirst() returned %d events, want 2", len(got))
		}
		if got[0].Timestamp.Before(got[1].Timestamp) {
			t.Error("newestFirst() did not order events newest first")
		}
	})
}

// compressFile gzips a rotated log file the way the rotator does.
func compressFile(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file for compression: %v", err)
	}

	out, err := os.Create(path + compressedSuffix)
	if err != nil {
		t.Fatalf("failed to create compressed file: %v", err)
	}
	defer func() { _ = out.Close() }()

	writer := gzip.NewWriter(out)
	if _, err := writer.Write(data); err != nil {
		t.Fatalf("failed to compress file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("failed to remove uncompressed file: %v", err)
	}
}
