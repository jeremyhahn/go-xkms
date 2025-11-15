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

package audit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryAuditAdapter_LogEvent(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		event := &AuditEvent{
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
			Action:    "Generate RSA key",
			Principal: &Principal{
				Type: "user",
				ID:   "user-123",
				Name: "Test User",
			},
			Resource: &Resource{
				Type:    "key",
				ID:      "key-456",
				Backend: "software",
			},
		}

		err := adapter.LogEvent(ctx, event)
		if err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}

		// Verify event was stored
		if event.ID == "" {
			t.Error("Event ID was not generated")
		}

		if event.Timestamp.IsZero() {
			t.Error("Event timestamp was not set")
		}

		// Retrieve and verify
		retrieved, err := adapter.GetEvent(ctx, event.ID)
		if err != nil {
			t.Fatalf("GetEvent failed: %v", err)
		}

		if retrieved.EventType != EventKeyGenerate {
			t.Errorf("Expected event type %s, got %s", EventKeyGenerate, retrieved.EventType)
		}
	})

	t.Run("NilEvent", func(t *testing.T) {
		err := adapter.LogEvent(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil event")
		}
	})

	t.Run("CustomIDAndTimestamp", func(t *testing.T) {
		customTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
		event := &AuditEvent{
			ID:        "custom-id-123",
			Timestamp: customTime,
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
		}

		err := adapter.LogEvent(ctx, event)
		if err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}

		if event.ID != "custom-id-123" {
			t.Errorf("Expected custom ID to be preserved, got %s", event.ID)
		}

		if !event.Timestamp.Equal(customTime) {
			t.Errorf("Expected custom timestamp to be preserved, got %v", event.Timestamp)
		}
	})
}

func TestMemoryAuditAdapter_GetEvent(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		event := &AuditEvent{
			ID:        "test-event-1",
			EventType: EventSign,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
		}

		err := adapter.LogEvent(ctx, event)
		if err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}

		retrieved, err := adapter.GetEvent(ctx, "test-event-1")
		if err != nil {
			t.Fatalf("GetEvent failed: %v", err)
		}

		if retrieved.ID != "test-event-1" {
			t.Errorf("Expected ID test-event-1, got %s", retrieved.ID)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := adapter.GetEvent(ctx, "non-existent-id")
		if err == nil {
			t.Error("Expected error for non-existent event")
		}
	})

	t.Run("EmptyID", func(t *testing.T) {
		_, err := adapter.GetEvent(ctx, "")
		if err == nil {
			t.Error("Expected error for empty event ID")
		}
	})
}

func TestMemoryAuditAdapter_GetEvents(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	// Setup test data
	now := time.Now()
	events := []*AuditEvent{
		{
			ID:        "event-1",
			Timestamp: now.Add(-5 * time.Minute),
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
			Principal: &Principal{ID: "user-1"},
			Resource:  &Resource{ID: "key-1", Backend: "software"},
			RequestID: "req-1",
			SessionID: "sess-1",
		},
		{
			ID:        "event-2",
			Timestamp: now.Add(-4 * time.Minute),
			EventType: EventSign,
			Severity:  SeverityWarn,
			Outcome:   OutcomeFailure,
			Principal: &Principal{ID: "user-2"},
			Resource:  &Resource{ID: "key-2", Backend: "pkcs11"},
			RequestID: "req-2",
			SessionID: "sess-2",
		},
		{
			ID:        "event-3",
			Timestamp: now.Add(-3 * time.Minute),
			EventType: EventKeyGenerate,
			Severity:  SeverityError,
			Outcome:   OutcomeSuccess,
			Principal: &Principal{ID: "user-1"},
			Resource:  &Resource{ID: "key-3", Backend: "software"},
			RequestID: "req-1",
			SessionID: "sess-1",
		},
	}

	for _, event := range events {
		if err := adapter.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	t.Run("AllEvents", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 3 {
			t.Errorf("Expected 3 events, got %d", len(results))
		}

		// Should be sorted by timestamp descending
		if !results[0].Timestamp.After(results[1].Timestamp) {
			t.Error("Events not sorted by timestamp descending")
		}
	})

	t.Run("FilterByEventType", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			EventTypes: []EventType{EventKeyGenerate},
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}

		for _, event := range results {
			if event.EventType != EventKeyGenerate {
				t.Errorf("Expected EventKeyGenerate, got %s", event.EventType)
			}
		}
	})

	t.Run("FilterBySeverity", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			Severities: []EventSeverity{SeverityInfo, SeverityWarn},
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}
	})

	t.Run("FilterByOutcome", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			Outcomes: []EventOutcome{OutcomeSuccess},
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}
	})

	t.Run("FilterByPrincipal", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			PrincipalID: "user-1",
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}
	})

	t.Run("FilterByResource", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			ResourceID: "key-2",
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 1 {
			t.Errorf("Expected 1 event, got %d", len(results))
		}
	})

	t.Run("FilterByBackend", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			Backend: "software",
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}
	})

	t.Run("FilterByTimeRange", func(t *testing.T) {
		startTime := now.Add(-4*time.Minute - 30*time.Second)
		endTime := now.Add(-3*time.Minute + 30*time.Second)

		results, err := adapter.GetEvents(ctx, &EventQuery{
			StartTime: &startTime,
			EndTime:   &endTime,
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}
	})

	t.Run("FilterByRequestID", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			RequestID: "req-1",
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 2 {
			t.Errorf("Expected 2 events, got %d", len(results))
		}
	})

	t.Run("FilterBySessionID", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			SessionID: "sess-2",
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 1 {
			t.Errorf("Expected 1 event, got %d", len(results))
		}
	})

	t.Run("LimitAndOffset", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			Limit:  1,
			Offset: 1,
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 1 {
			t.Errorf("Expected 1 event, got %d", len(results))
		}
	})

	t.Run("OrderByTimestampAsc", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, &EventQuery{
			OrderBy: "timestamp_asc",
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) < 2 {
			t.Fatal("Not enough results to test ordering")
		}

		// Should be sorted by timestamp ascending
		if !results[0].Timestamp.Before(results[1].Timestamp) {
			t.Error("Events not sorted by timestamp ascending")
		}
	})

	t.Run("NilQuery", func(t *testing.T) {
		results, err := adapter.GetEvents(ctx, nil)
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 3 {
			t.Errorf("Expected 3 events, got %d", len(results))
		}
	})
}

func TestMemoryAuditAdapter_DeleteEvent(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		event := &AuditEvent{
			ID:        "delete-test-1",
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
		}

		err := adapter.LogEvent(ctx, event)
		if err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}

		err = adapter.DeleteEvent(ctx, "delete-test-1")
		if err != nil {
			t.Fatalf("DeleteEvent failed: %v", err)
		}

		// Verify event is deleted
		_, err = adapter.GetEvent(ctx, "delete-test-1")
		if err == nil {
			t.Error("Expected error when getting deleted event")
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		err := adapter.DeleteEvent(ctx, "non-existent-id")
		if err == nil {
			t.Error("Expected error for non-existent event")
		}
	})

	t.Run("EmptyID", func(t *testing.T) {
		err := adapter.DeleteEvent(ctx, "")
		if err == nil {
			t.Error("Expected error for empty event ID")
		}
	})
}

func TestMemoryAuditAdapter_DeleteEvents(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	// Setup test data
	events := []*AuditEvent{
		{
			ID:        "bulk-delete-1",
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
		},
		{
			ID:        "bulk-delete-2",
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
		},
		{
			ID:        "bulk-delete-3",
			EventType: EventSign,
			Severity:  SeverityWarn,
			Outcome:   OutcomeFailure,
		},
	}

	for _, event := range events {
		if err := adapter.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	t.Run("Success", func(t *testing.T) {
		count, err := adapter.DeleteEvents(ctx, &EventQuery{
			EventTypes: []EventType{EventKeyGenerate},
		})
		if err != nil {
			t.Fatalf("DeleteEvents failed: %v", err)
		}

		if count != 2 {
			t.Errorf("Expected 2 deleted events, got %d", count)
		}

		// Verify events are deleted
		results, err := adapter.GetEvents(ctx, &EventQuery{
			EventTypes: []EventType{EventKeyGenerate},
		})
		if err != nil {
			t.Fatalf("GetEvents failed: %v", err)
		}

		if len(results) != 0 {
			t.Errorf("Expected 0 events after deletion, got %d", len(results))
		}
	})

	t.Run("NilQuery", func(t *testing.T) {
		_, err := adapter.DeleteEvents(ctx, nil)
		if err == nil {
			t.Error("Expected error for nil query")
		}
	})
}

func TestMemoryAuditAdapter_GetStatistics(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	// Setup test data
	now := time.Now()
	events := []*AuditEvent{
		{
			Timestamp: now.Add(-2 * time.Hour),
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
			Principal: &Principal{ID: "user-1"},
			Resource:  &Resource{ID: "key-1"},
		},
		{
			Timestamp: now.Add(-1 * time.Hour),
			EventType: EventKeyGenerate,
			Severity:  SeverityInfo,
			Outcome:   OutcomeSuccess,
			Principal: &Principal{ID: "user-1"},
			Resource:  &Resource{ID: "key-2"},
		},
		{
			Timestamp: now.Add(-30 * time.Minute),
			EventType: EventSign,
			Severity:  SeverityWarn,
			Outcome:   OutcomeFailure,
			Principal: &Principal{ID: "user-2"},
			Resource:  &Resource{ID: "key-1"},
		},
		{
			Timestamp: now.Add(-15 * time.Minute),
			EventType: EventVerify,
			Severity:  SeverityError,
			Outcome:   OutcomeDenied,
			Principal: &Principal{ID: "user-3"},
			Resource:  &Resource{ID: "key-3"},
		},
	}

	for _, event := range events {
		if err := adapter.LogEvent(ctx, event); err != nil {
			t.Fatalf("LogEvent failed: %v", err)
		}
	}

	t.Run("AllStatistics", func(t *testing.T) {
		stats, err := adapter.GetStatistics(ctx, &StatisticsQuery{})
		if err != nil {
			t.Fatalf("GetStatistics failed: %v", err)
		}

		if stats.TotalEvents != 4 {
			t.Errorf("Expected 4 total events, got %d", stats.TotalEvents)
		}

		if stats.EventsByType[EventKeyGenerate] != 2 {
			t.Errorf("Expected 2 EventKeyGenerate, got %d", stats.EventsByType[EventKeyGenerate])
		}

		if stats.EventsBySeverity[SeverityInfo] != 2 {
			t.Errorf("Expected 2 SeverityInfo events, got %d", stats.EventsBySeverity[SeverityInfo])
		}

		if stats.EventsByOutcome[OutcomeSuccess] != 2 {
			t.Errorf("Expected 2 OutcomeSuccess events, got %d", stats.EventsByOutcome[OutcomeSuccess])
		}

		if len(stats.TopPrincipals) == 0 {
			t.Error("Expected top principals to be populated")
		}

		if stats.TopPrincipals[0].PrincipalID != "user-1" {
			t.Errorf("Expected top principal to be user-1, got %s", stats.TopPrincipals[0].PrincipalID)
		}

		if stats.TopPrincipals[0].EventCount != 2 {
			t.Errorf("Expected user-1 to have 2 events, got %d", stats.TopPrincipals[0].EventCount)
		}

		if len(stats.TopResources) == 0 {
			t.Error("Expected top resources to be populated")
		}
	})

	t.Run("TimeRangeFilter", func(t *testing.T) {
		startTime := now.Add(-1*time.Hour - 30*time.Minute)
		endTime := now.Add(-20 * time.Minute)

		stats, err := adapter.GetStatistics(ctx, &StatisticsQuery{
			StartTime: &startTime,
			EndTime:   &endTime,
		})
		if err != nil {
			t.Fatalf("GetStatistics failed: %v", err)
		}

		if stats.TotalEvents != 2 {
			t.Errorf("Expected 2 total events in time range, got %d", stats.TotalEvents)
		}
	})

	t.Run("NilQuery", func(t *testing.T) {
		stats, err := adapter.GetStatistics(ctx, nil)
		if err != nil {
			t.Fatalf("GetStatistics failed: %v", err)
		}

		if stats.TotalEvents != 4 {
			t.Errorf("Expected 4 total events, got %d", stats.TotalEvents)
		}
	})
}

func TestMemoryAuditAdapter_ConcurrentAccess(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	const numGoroutines = 100
	const eventsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(routineID int) {
			defer wg.Done()

			for j := 0; j < eventsPerGoroutine; j++ {
				event := &AuditEvent{
					EventType: EventKeyGenerate,
					Severity:  SeverityInfo,
					Outcome:   OutcomeSuccess,
					Principal: &Principal{ID: "concurrent-user"},
					Resource:  &Resource{ID: "concurrent-key"},
				}

				if err := adapter.LogEvent(ctx, event); err != nil {
					t.Errorf("LogEvent failed: %v", err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify all events were logged
	events, err := adapter.GetEvents(ctx, &EventQuery{})
	if err != nil {
		t.Fatalf("GetEvents failed: %v", err)
	}

	expectedCount := numGoroutines * eventsPerGoroutine
	if len(events) != expectedCount {
		t.Errorf("Expected %d events, got %d", expectedCount, len(events))
	}

	// Concurrent reads
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			_, err := adapter.GetEvents(ctx, &EventQuery{})
			if err != nil {
				t.Errorf("GetEvents failed: %v", err)
			}
		}()
	}

	wg.Wait()

	// Concurrent statistics
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			_, err := adapter.GetStatistics(ctx, &StatisticsQuery{})
			if err != nil {
				t.Errorf("GetStatistics failed: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestMemoryAuditAdapter_TopPrincipalsAndResources(t *testing.T) {
	adapter := NewMemoryAuditAdapter()
	ctx := context.Background()

	// Create events with varying principals and resources
	for i := 0; i < 15; i++ {
		for j := 0; j <= i; j++ {
			event := &AuditEvent{
				EventType: EventKeyGenerate,
				Severity:  SeverityInfo,
				Outcome:   OutcomeSuccess,
				Principal: &Principal{ID: string(rune('A' + i))},
				Resource:  &Resource{ID: string(rune('a' + i))},
			}

			if err := adapter.LogEvent(ctx, event); err != nil {
				t.Fatalf("LogEvent failed: %v", err)
			}
		}
	}

	stats, err := adapter.GetStatistics(ctx, &StatisticsQuery{})
	if err != nil {
		t.Fatalf("GetStatistics failed: %v", err)
	}

	// Should return top 10 principals
	if len(stats.TopPrincipals) != 10 {
		t.Errorf("Expected top 10 principals, got %d", len(stats.TopPrincipals))
	}

	// Should be sorted by count descending
	for i := 0; i < len(stats.TopPrincipals)-1; i++ {
		if stats.TopPrincipals[i].EventCount < stats.TopPrincipals[i+1].EventCount {
			t.Error("Top principals not sorted by count descending")
		}
	}

	// Should return top 10 resources
	if len(stats.TopResources) != 10 {
		t.Errorf("Expected top 10 resources, got %d", len(stats.TopResources))
	}

	// Should be sorted by count descending
	for i := 0; i < len(stats.TopResources)-1; i++ {
		if stats.TopResources[i].EventCount < stats.TopResources[i+1].EventCount {
			t.Error("Top resources not sorted by count descending")
		}
	}
}
