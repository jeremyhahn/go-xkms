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

/*
Package audit provides an adapter pattern for audit logging in go-keychain.

# Overview

The audit adapter pattern allows applications to implement custom audit trail
strategies while maintaining a consistent interface throughout go-keychain.
This follows the same design principles as the auth and logger adapters.

# Architecture

The audit system consists of:

1. AuditAdapter Interface - Defines the contract for audit logging implementations
2. AuditEvent - Represents a single audit log entry with comprehensive metadata
3. EventQuery - Provides filtering and pagination for event retrieval
4. Statistics - Aggregates audit data for reporting and analysis

# Event Types

Audit events are categorized by type to support filtering and analysis:

  - Key Management: generate, import, export, rotate, delete
  - Cryptographic Operations: sign, verify, encrypt, decrypt
  - Certificates: create, sign, revoke, renew, import, export
  - Authentication: success, failure, logout
  - Authorization: allow, deny
  - Administrative: config changes, backend management, policies
  - System: start, stop, errors

# Event Attributes

Each audit event contains:

  - Unique ID and timestamp
  - Event type, severity, and outcome
  - Principal (who performed the action)
  - Resource (what was accessed)
  - Action description and result
  - Request/session correlation IDs
  - Client metadata (IP, user agent)
  - Custom metadata map

# Implementations

# MemoryAuditAdapter

The package includes a thread-safe in-memory implementation suitable for:

  - Development and testing
  - Small-scale deployments
  - Scenarios where persistent logs are not required

Note: In-memory events are lost on process restart.

# Custom Implementations

Applications can implement the AuditAdapter interface to provide:

  - Database-backed persistent storage
  - SIEM integration (Splunk, ELK, etc.)
  - Cloud logging services (CloudWatch, Stackdriver, etc.)
  - Distributed tracing systems
  - Write-ahead logging with rotation
  - Compliance-focused immutable logs

# Usage Examples

Basic Logging:

	adapter := audit.NewMemoryAuditAdapter()

	event := &audit.AuditEvent{
		EventType: audit.EventKeyGenerate,
		Severity:  audit.SeverityInfo,
		Outcome:   audit.OutcomeSuccess,
		Action:    "Generate RSA-2048 key",
		Principal: &audit.Principal{
			Type: "user",
			ID:   "alice@example.com",
			Name: "Alice",
		},
		Resource: &audit.Resource{
			Type:    "key",
			ID:      "key-123",
			Backend: "software",
		},
	}

	if err := adapter.LogEvent(context.Background(), event); err != nil {
		log.Fatalf("Failed to log event: %v", err)
	}

Querying Events:

	// Get all key generation events in the last hour
	oneHourAgo := time.Now().Add(-1 * time.Hour)

	events, err := adapter.GetEvents(context.Background(), &audit.EventQuery{
		EventTypes: []audit.EventType{audit.EventKeyGenerate},
		StartTime:  &oneHourAgo,
		Limit:      100,
	})

	// Get events for a specific user
	events, err = adapter.GetEvents(context.Background(), &audit.EventQuery{
		PrincipalID: "alice@example.com",
	})

	// Get failed operations
	events, err = adapter.GetEvents(context.Background(), &audit.EventQuery{
		Outcomes: []audit.EventOutcome{audit.OutcomeFailure},
		Severities: []audit.EventSeverity{
			audit.SeverityError,
			audit.SeverityCritical,
		},
	})

Statistics and Reporting:

	stats, err := adapter.GetStatistics(context.Background(), &audit.StatisticsQuery{})
	if err != nil {
		log.Fatalf("Failed to get statistics: %v", err)
	}

	fmt.Printf("Total events: %d\n", stats.TotalEvents)
	fmt.Printf("Success rate: %.2f%%\n",
		float64(stats.EventsByOutcome[audit.OutcomeSuccess]) /
		float64(stats.TotalEvents) * 100)

	fmt.Println("Top users:")
	for i, principal := range stats.TopPrincipals {
		fmt.Printf("%d. %s: %d events\n",
			i+1, principal.PrincipalID, principal.EventCount)
	}

Event Deletion (GDPR Compliance):

	// Delete specific event
	if err := adapter.DeleteEvent(context.Background(), eventID); err != nil {
		log.Fatalf("Failed to delete event: %v", err)
	}

	// Delete all events for a principal (right to be forgotten)
	count, err := adapter.DeleteEvents(context.Background(), &audit.EventQuery{
		PrincipalID: "user@example.com",
	})
	fmt.Printf("Deleted %d events\n", count)

# Compliance Considerations

When implementing audit adapters for regulated environments:

1. Immutability - Events should not be modifiable after creation
2. Integrity - Consider cryptographic signatures or hash chains
3. Retention - Implement appropriate retention policies
4. Encryption - Protect sensitive data in audit logs
5. Access Control - Restrict who can query/delete audit events
6. Completeness - Ensure all security-relevant events are logged
7. Availability - Maintain high availability for audit systems
8. Monitoring - Alert on audit system failures

# Security Best Practices

1. Sanitize sensitive data before logging
2. Avoid logging secrets, keys, or credentials
3. Log both successes and failures
4. Include sufficient context for forensics
5. Protect audit logs with strong access controls
6. Monitor for gaps in audit trails
7. Implement tamper detection mechanisms
8. Regular audit log reviews

# Performance Considerations

For high-throughput systems:

1. Use buffered/batched writes
2. Consider async logging to avoid blocking
3. Implement log rotation and archival
4. Use efficient storage backends
5. Index frequently queried fields
6. Partition data by time or tenant
7. Monitor audit system performance
8. Set appropriate retention limits

# Thread Safety

All AuditAdapter implementations must be thread-safe and support
concurrent access from multiple goroutines.

# Error Handling

Audit operations should fail gracefully:

1. Log errors but don't block main operations
2. Use circuit breakers for failing backends
3. Implement retry logic with backoff
4. Provide fallback mechanisms
5. Alert on persistent failures

# Integration

The audit adapter integrates with go-keychain's middleware and
backend operations to automatically log security-relevant events
throughout the system.
*/
package audit
