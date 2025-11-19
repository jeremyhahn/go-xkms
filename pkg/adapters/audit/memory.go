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
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// MemoryAuditAdapter implements AuditAdapter with in-memory storage.
// This implementation is thread-safe and suitable for development, testing,
// or scenarios where persistent audit logs are not required.
//
// Note: All events are stored in memory and will be lost on process restart.
// For production use, consider implementing a persistent storage backend.
type MemoryAuditAdapter struct {
	events   sync.Map // map[string]*AuditEvent
	eventIDs []string // Ordered list of event IDs for iteration
	mu       sync.RWMutex
	counter  atomic.Int64
}

// NewMemoryAuditAdapter creates a new in-memory audit adapter
func NewMemoryAuditAdapter() *MemoryAuditAdapter {
	return &MemoryAuditAdapter{
		eventIDs: make([]string, 0, 1024),
	}
}

// LogEvent records an audit event in memory
func (m *MemoryAuditAdapter) LogEvent(ctx context.Context, event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Generate ID if not provided
	if event.ID == "" {
		event.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Store the event
	m.events.Store(event.ID, event)

	// Add to ordered list
	m.mu.Lock()
	m.eventIDs = append(m.eventIDs, event.ID)
	m.mu.Unlock()

	m.counter.Add(1)

	return nil
}

// GetEvents retrieves audit events based on query parameters
func (m *MemoryAuditAdapter) GetEvents(ctx context.Context, query *EventQuery) ([]*AuditEvent, error) {
	if query == nil {
		query = &EventQuery{}
	}

	var results []*AuditEvent

	// Get all events in order
	m.mu.RLock()
	eventIDsCopy := make([]string, len(m.eventIDs))
	copy(eventIDsCopy, m.eventIDs)
	m.mu.RUnlock()

	for _, id := range eventIDsCopy {
		value, ok := m.events.Load(id)
		if !ok {
			continue
		}

		event := value.(*AuditEvent)
		if m.matchesQuery(event, query) {
			results = append(results, event)
		}
	}

	// Sort by timestamp descending (newest first) unless otherwise specified
	// Sort by timestamp descending (newest first) unless otherwise specified
	switch query.OrderBy {
	case "", "timestamp_desc":
		sort.Slice(results, func(i, j int) bool {
			return results[i].Timestamp.After(results[j].Timestamp)
		})
	case "timestamp_asc":
		sort.Slice(results, func(i, j int) bool {
			return results[i].Timestamp.Before(results[j].Timestamp)
		})
	}

	// Apply offset and limit
	if query.Offset > 0 {
		if query.Offset >= len(results) {
			return []*AuditEvent{}, nil
		}
		results = results[query.Offset:]
	}

	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}

	return results, nil
}

// GetEvent retrieves a specific audit event by ID
func (m *MemoryAuditAdapter) GetEvent(ctx context.Context, eventID string) (*AuditEvent, error) {
	if eventID == "" {
		return nil, fmt.Errorf("event ID cannot be empty")
	}

	value, ok := m.events.Load(eventID)
	if !ok {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	return value.(*AuditEvent), nil
}

// DeleteEvent removes an audit event by ID
func (m *MemoryAuditAdapter) DeleteEvent(ctx context.Context, eventID string) error {
	if eventID == "" {
		return fmt.Errorf("event ID cannot be empty")
	}

	// Check if event exists
	_, ok := m.events.LoadAndDelete(eventID)
	if !ok {
		return fmt.Errorf("event not found: %s", eventID)
	}

	// Remove from ordered list
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, id := range m.eventIDs {
		if id == eventID {
			m.eventIDs = append(m.eventIDs[:i], m.eventIDs[i+1:]...)
			break
		}
	}

	m.counter.Add(-1)

	return nil
}

// DeleteEvents removes multiple audit events matching a query
func (m *MemoryAuditAdapter) DeleteEvents(ctx context.Context, query *EventQuery) (int, error) {
	if query == nil {
		return 0, fmt.Errorf("query cannot be nil")
	}

	events, err := m.GetEvents(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to get events: %w", err)
	}

	count := 0
	for _, event := range events {
		if err := m.DeleteEvent(ctx, event.ID); err == nil {
			count++
		}
	}

	return count, nil
}

// GetStatistics returns audit statistics
func (m *MemoryAuditAdapter) GetStatistics(ctx context.Context, query *StatisticsQuery) (*Statistics, error) {
	if query == nil {
		query = &StatisticsQuery{}
	}

	stats := &Statistics{
		EventsByType:     make(map[EventType]int64),
		EventsBySeverity: make(map[EventSeverity]int64),
		EventsByOutcome:  make(map[EventOutcome]int64),
	}

	principalCounts := make(map[string]int64)
	resourceCounts := make(map[string]int64)

	// Iterate through all events
	m.events.Range(func(key, value interface{}) bool {
		event := value.(*AuditEvent)

		// Apply time filters
		if query.StartTime != nil && event.Timestamp.Before(*query.StartTime) {
			return true
		}
		if query.EndTime != nil && event.Timestamp.After(*query.EndTime) {
			return true
		}

		// Count total events
		stats.TotalEvents++

		// Count by type
		stats.EventsByType[event.EventType]++

		// Count by severity
		stats.EventsBySeverity[event.Severity]++

		// Count by outcome
		stats.EventsByOutcome[event.Outcome]++

		// Count by principal
		if event.Principal != nil && event.Principal.ID != "" {
			principalCounts[event.Principal.ID]++
		}

		// Count by resource
		if event.Resource != nil && event.Resource.ID != "" {
			resourceCounts[event.Resource.ID]++
		}

		return true
	})

	// Build top principals list
	stats.TopPrincipals = m.buildTopPrincipals(principalCounts)

	// Build top resources list
	stats.TopResources = m.buildTopResources(resourceCounts)

	return stats, nil
}

// matchesQuery checks if an event matches the query criteria
func (m *MemoryAuditAdapter) matchesQuery(event *AuditEvent, query *EventQuery) bool {
	// Filter by event types
	if len(query.EventTypes) > 0 {
		matched := false
		for _, et := range query.EventTypes {
			if event.EventType == et {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by severities
	if len(query.Severities) > 0 {
		matched := false
		for _, s := range query.Severities {
			if event.Severity == s {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by outcomes
	if len(query.Outcomes) > 0 {
		matched := false
		for _, o := range query.Outcomes {
			if event.Outcome == o {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by principal ID
	if query.PrincipalID != "" {
		if event.Principal == nil || event.Principal.ID != query.PrincipalID {
			return false
		}
	}

	// Filter by resource ID
	if query.ResourceID != "" {
		if event.Resource == nil || event.Resource.ID != query.ResourceID {
			return false
		}
	}

	// Filter by backend
	if query.Backend != "" {
		if event.Resource == nil || event.Resource.Backend != query.Backend {
			return false
		}
	}

	// Filter by start time
	if query.StartTime != nil && event.Timestamp.Before(*query.StartTime) {
		return false
	}

	// Filter by end time
	if query.EndTime != nil && event.Timestamp.After(*query.EndTime) {
		return false
	}

	// Filter by request ID
	if query.RequestID != "" && event.RequestID != query.RequestID {
		return false
	}

	// Filter by session ID
	if query.SessionID != "" && event.SessionID != query.SessionID {
		return false
	}

	return true
}

// buildTopPrincipals builds a sorted list of top principals by event count
func (m *MemoryAuditAdapter) buildTopPrincipals(counts map[string]int64) []PrincipalStats {
	principals := make([]PrincipalStats, 0, len(counts))
	for id, count := range counts {
		principals = append(principals, PrincipalStats{
			PrincipalID: id,
			EventCount:  count,
		})
	}

	// Sort by count descending
	sort.Slice(principals, func(i, j int) bool {
		return principals[i].EventCount > principals[j].EventCount
	})

	// Return top 10
	if len(principals) > 10 {
		principals = principals[:10]
	}

	return principals
}

// buildTopResources builds a sorted list of top resources by event count
func (m *MemoryAuditAdapter) buildTopResources(counts map[string]int64) []ResourceStats {
	resources := make([]ResourceStats, 0, len(counts))
	for id, count := range counts {
		resources = append(resources, ResourceStats{
			ResourceID: id,
			EventCount: count,
		})
	}

	// Sort by count descending
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].EventCount > resources[j].EventCount
	})

	// Return top 10
	if len(resources) > 10 {
		resources = resources[:10]
	}

	return resources
}
