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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileLogger_NewFileLogger(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "audit.log")

		logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		defer func() { _ = logger.Close() }()

		// Verify the file was created with correct permissions
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("expected file to exist: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
		}
	})

	t.Run("EmptyPath", func(t *testing.T) {
		_, err := NewFileLogger(&FileLoggerConfig{Path: ""})
		if err == nil {
			t.Fatal("expected error for empty path")
		}
	})

	t.Run("NilConfig", func(t *testing.T) {
		_, err := NewFileLogger(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})
}

func TestFileLogger_Log_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	event := &Event{
		Timestamp:  time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC),
		Subject:    "alice@example.com",
		Action:     "key.generate",
		Resource:   "keys",
		ResourceID: "rsa-2048-001",
		Outcome:    OutcomeAllow,
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Subject != "alice@example.com" {
		t.Errorf("expected subject alice@example.com, got %s", decoded.Subject)
	}
	if decoded.Action != "key.generate" {
		t.Errorf("expected action key.generate, got %s", decoded.Action)
	}
	if decoded.Resource != "keys" {
		t.Errorf("expected resource keys, got %s", decoded.Resource)
	}
	if decoded.ResourceID != "rsa-2048-001" {
		t.Errorf("expected resource_id rsa-2048-001, got %s", decoded.ResourceID)
	}
	if decoded.Outcome != OutcomeAllow {
		t.Errorf("expected outcome allow, got %s", decoded.Outcome)
	}
	if !decoded.Timestamp.Equal(event.Timestamp) {
		t.Errorf("expected timestamp %v, got %v", event.Timestamp, decoded.Timestamp)
	}
}

func TestFileLogger_Log_NilEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	err = logger.Log(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil event")
	}
	if !errors.Is(err, ErrNilEvent) {
		t.Errorf("expected ErrNilEvent, got: %v", err)
	}
}

func TestFileLogger_Log_AfterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = logger.Log(context.Background(), &Event{
		Subject: "bob",
		Action:  "key.get",
	})
	if err == nil {
		t.Fatal("expected error after close")
	}
	if !errors.Is(err, ErrLoggerClosed) {
		t.Errorf("expected ErrLoggerClosed, got: %v", err)
	}
}

func TestFileLogger_Log_SetsTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	before := time.Now().UTC()

	event := &Event{
		Subject:    "system",
		Action:     "system.start",
		Resource:   "system",
		ResourceID: "xkmsd",
		Outcome:    OutcomeAllow,
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	after := time.Now().UTC()

	// Read back
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Timestamp.IsZero() {
		t.Fatal("expected timestamp to be set")
	}
	if decoded.Timestamp.Before(before) || decoded.Timestamp.After(after) {
		t.Errorf("timestamp %v not in expected range [%v, %v]", decoded.Timestamp, before, after)
	}
}

func TestFileLogger_Log_PreservesTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	fixedTime := time.Date(2024, 3, 15, 8, 0, 0, 0, time.UTC)
	event := &Event{
		Timestamp:  fixedTime,
		Subject:    "admin",
		Action:     "config.change",
		Resource:   "config",
		ResourceID: "tls-cert-path",
		Outcome:    OutcomeAllow,
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !decoded.Timestamp.Equal(fixedTime) {
		t.Errorf("expected timestamp %v preserved, got %v", fixedTime, decoded.Timestamp)
	}
}

func TestFileLogger_Log_MultipleEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	events := []*Event{
		{
			Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Subject:    "alice",
			Action:     "key.generate",
			Resource:   "keys",
			ResourceID: "key-1",
			Outcome:    OutcomeAllow,
		},
		{
			Timestamp:  time.Date(2025, 1, 1, 0, 1, 0, 0, time.UTC),
			Subject:    "bob",
			Action:     "cert.sign",
			Resource:   "certs",
			ResourceID: "cert-1",
			Outcome:    OutcomeDeny,
		},
		{
			Timestamp:  time.Date(2025, 1, 1, 0, 2, 0, 0, time.UTC),
			Subject:    "carol",
			Action:     "key.export",
			Resource:   "keys",
			ResourceID: "key-2",
			Outcome:    OutcomeAllow,
		},
	}

	for _, ev := range events {
		if err := logger.Log(context.Background(), ev); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// Read back all lines
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	var decoded []Event
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("Unmarshal line: %v", err)
		}
		decoded = append(decoded, ev)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner: %v", err)
	}

	if len(decoded) != 3 {
		t.Fatalf("expected 3 events, got %d", len(decoded))
	}

	if decoded[0].Subject != "alice" {
		t.Errorf("event 0: expected subject alice, got %s", decoded[0].Subject)
	}
	if decoded[1].Subject != "bob" {
		t.Errorf("event 1: expected subject bob, got %s", decoded[1].Subject)
	}
	if decoded[2].Subject != "carol" {
		t.Errorf("event 2: expected subject carol, got %s", decoded[2].Subject)
	}
	if decoded[1].Outcome != OutcomeDeny {
		t.Errorf("event 1: expected outcome deny, got %s", decoded[1].Outcome)
	}
}

func TestFileLogger_Log_WithDetails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	event := &Event{
		Timestamp:  time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		Subject:    "admin@example.com",
		Action:     "key.rotate",
		Resource:   "keys",
		ResourceID: "signing-key-prod",
		Outcome:    OutcomeAllow,
		Details: map[string]string{
			"algorithm":  "ECDSA-P256",
			"backend":    "pkcs11",
			"source_ip":  "10.0.0.5",
			"request_id": "req-abc-123",
		},
	}

	if err := logger.Log(context.Background(), event); err != nil {
		t.Fatalf("Log: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data[:len(data)-1], &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(decoded.Details) != 4 {
		t.Fatalf("expected 4 details entries, got %d", len(decoded.Details))
	}
	if decoded.Details["algorithm"] != "ECDSA-P256" {
		t.Errorf("expected algorithm ECDSA-P256, got %s", decoded.Details["algorithm"])
	}
	if decoded.Details["backend"] != "pkcs11" {
		t.Errorf("expected backend pkcs11, got %s", decoded.Details["backend"])
	}
	if decoded.Details["source_ip"] != "10.0.0.5" {
		t.Errorf("expected source_ip 10.0.0.5, got %s", decoded.Details["source_ip"])
	}
	if decoded.Details["request_id"] != "req-abc-123" {
		t.Errorf("expected request_id req-abc-123, got %s", decoded.Details["request_id"])
	}
}

func TestFileLogger_Close_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("second Close: expected nil, got: %v", err)
	}
}

func TestFileLogger_InterfaceCompliance(t *testing.T) {
	var _ Logger = (*FileLogger)(nil)
}

func TestFileLogger_Log_ConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	logger, err := NewFileLogger(&FileLoggerConfig{Path: path})
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	defer func() { _ = logger.Close() }()

	const numGoroutines = 50
	const eventsPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := &Event{
					Timestamp:  time.Now().UTC(),
					Subject:    "concurrent-user",
					Action:     "key.get",
					Resource:   "keys",
					ResourceID: "concurrent-key",
					Outcome:    OutcomeAllow,
				}
				if err := logger.Log(context.Background(), event); err != nil {
					t.Errorf("goroutine %d event %d: Log: %v", routineID, j, err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Read back and count lines
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	lineCount := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var ev Event
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("line %d: Unmarshal: %v", lineCount+1, err)
		}
		lineCount++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("Scanner: %v", err)
	}

	expected := numGoroutines * eventsPerGoroutine
	if lineCount != expected {
		t.Errorf("expected %d lines, got %d", expected, lineCount)
	}
}
