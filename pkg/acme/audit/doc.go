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

// Package audit provides production-grade audit logging for the go-trusted-ca
// Certificate Authority and ACME server.
//
// The audit system tracks comprehensive security-relevant events including:
//   - Certificate lifecycle (issuance, renewal, revocation)
//   - Account management (creation, updates, deactivation, key changes)
//   - Authorization and challenge validation
//   - TPM enrollment and attestation
//   - Authentication failures and security events
//
// Features:
//   - Structured JSON logging with automatic rotation
//   - Buffered writes for high performance
//   - Thread-safe concurrent logging
//   - Configurable retention policies
//   - HTTP middleware for automatic request auditing
//   - Context propagation for request correlation
//
// Example usage:
//
//	config := &audit.Config{
//		Enabled:              true,
//		LogPath:              "/var/log/acme/audit.log",
//		MaxSizeMB:            100,
//		MaxAgeDays:           365,
//		Format:               "json",
//		BufferSize:           100,
//		FlushIntervalSeconds: 5,
//	}
//
//	logger, err := audit.NewFileAuditLogger(config)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer logger.Close()
//
//	// Log a certificate issuance
//	ctx := context.Background()
//	err = audit.LogCertificateIssued(
//		ctx, logger,
//		"account:123",
//		"order:456",
//		"example.com",
//		90,
//		"ABC123",
//	)
//
// All audit events are written as structured JSON:
//
//	{
//		"timestamp": "2025-01-15T10:30:00Z",
//		"event_type": "CERTIFICATE_ISSUED",
//		"actor": "account:123",
//		"resource": "order:456",
//		"action": "finalize",
//		"result": "success",
//		"request_id": "req-123",
//		"source_ip": "192.168.1.1",
//		"details": {
//			"common_name": "example.com",
//			"validity_days": 90,
//			"serial_number": "ABC123"
//		}
//	}
package audit
