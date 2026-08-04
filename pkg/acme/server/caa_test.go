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

package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDNSServer provides a mock DNS server for testing CAA validation.
type mockDNSServer struct {
	caaRecords  map[string][]*dns.CAA
	cnameRecord map[string]string
	rcode       map[string]int
}

func newMockDNSServer() *mockDNSServer {
	return &mockDNSServer{
		caaRecords:  make(map[string][]*dns.CAA),
		cnameRecord: make(map[string]string),
		rcode:       make(map[string]int),
	}
}

func (m *mockDNSServer) addCAARecord(domain, tag, value string) {
	fqdn := dns.Fqdn(domain)
	m.caaRecords[fqdn] = append(m.caaRecords[fqdn], &dns.CAA{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeCAA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Tag:   tag,
		Value: value,
		Flag:  0,
	})
}

func (m *mockDNSServer) addCNAME(domain, target string) {
	m.cnameRecord[dns.Fqdn(domain)] = target
}

func (m *mockDNSServer) setRcode(domain string, rcode int) {
	m.rcode[dns.Fqdn(domain)] = rcode
}

func (m *mockDNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(msg)
		return
	}

	q := r.Question[0]

	// Check for custom rcode
	if rcode, ok := m.rcode[q.Name]; ok {
		msg.Rcode = rcode
		_ = w.WriteMsg(msg)
		return
	}

	switch q.Qtype {
	case dns.TypeCAA:
		if records, ok := m.caaRecords[q.Name]; ok {
			for _, record := range records {
				msg.Answer = append(msg.Answer, record)
			}
		}
	case dns.TypeCNAME:
		if target, ok := m.cnameRecord[q.Name]; ok {
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: dns.Fqdn(target),
			})
		}
	}

	_ = w.WriteMsg(msg)
}

func startMockDNSServer(t *testing.T, mock *mockDNSServer) string {
	// Pre-bind the UDP socket to get the address before starting the server
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create UDP listener: %v", err)
	}

	addr := conn.LocalAddr().String()

	server := &dns.Server{
		PacketConn: conn,
		Handler:    dns.HandlerFunc(mock.handleDNS),
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() {
		close(started)
	}

	go func() {
		if err := server.ActivateAndServe(); err != nil {
			t.Logf("Mock DNS server error: %v", err)
		}
	}()

	// Wait for server to be ready
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for mock DNS server to start")
	}

	t.Cleanup(func() {
		_ = server.Shutdown()
	})

	return addr
}

func TestNewCAAValidator(t *testing.T) {
	tests := []struct {
		name        string
		params      *CAAValidatorParams
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil params",
			params:      nil,
			expectError: true,
			errorMsg:    "params cannot be nil",
		},
		{
			name: "nil logger",
			params: &CAAValidatorParams{
				Logger: nil,
			},
			expectError: true,
			errorMsg:    "logger is required",
		},
		{
			name: "valid params with defaults",
			params: &CAAValidatorParams{
				Logger: slog.Default(),
			},
			expectError: false,
		},
		{
			name: "valid params with custom resolver",
			params: &CAAValidatorParams{
				Logger:        slog.Default(),
				Resolver:      "1.1.1.1:53",
				Timeout:       10 * time.Second,
				CAAIdentities: []string{"ca.example.com"},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewCAAValidator(tt.params)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)
				assert.NotNil(t, validator.client)
				assert.NotNil(t, validator.cache)
			}
		})
	}
}

func TestCAAValidator_Validate_NoCAARecords(t *testing.T) {
	mock := newMockDNSServer()
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should allow issuance when no CAA records exist")
}

func TestCAAValidator_Validate_MatchingIssue(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should allow issuance with matching issue CAA record")
}

func TestCAAValidator_Validate_NoMatchingIssue(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "other-ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Should return CAA validation error")
	assert.Contains(t, err.Error(), "no matching issue CAA record found")
}

func TestCAAValidator_Validate_WildcardWithIssuewild(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issuewild", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", true)
	assert.NoError(t, err, "Should allow wildcard issuance with matching issuewild CAA record")
}

func TestCAAValidator_Validate_WildcardNoIssuewild(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issuewild", ";") // Explicitly deny wildcard
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", true)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Should deny wildcard when issuewild is ;")
}

func TestCAAValidator_Validate_WildcardFallbackToIssue(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	// No issuewild record - should fall back to issue tag
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", true)
	assert.NoError(t, err, "Should allow wildcard issuance with matching issue CAA record when no issuewild")
}

func TestCAAValidator_Validate_TreeClimbing(t *testing.T) {
	mock := newMockDNSServer()
	// No CAA at subdomain, but CAA at parent domain
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "sub.example.com", false)
	assert.NoError(t, err, "Should find CAA record by climbing to parent domain")
}

func TestCAAValidator_Validate_CNAMEFollowing(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCNAME("alias.example.com", "target.example.com")
	mock.addCAARecord("target.example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "alias.example.com", false)
	assert.NoError(t, err, "Should follow CNAME and find CAA record")
}

func TestCAAValidator_Validate_Iodef(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	mock.addCAARecord("example.com", "iodef", "mailto:security@example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should handle iodef records and allow issuance")
}

func TestCAAValidator_Validate_DNSServfail(t *testing.T) {
	mock := newMockDNSServer()
	mock.setRcode("example.com", dns.RcodeServerFailure)
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	// Per RFC 8659 Section 3, SERVFAIL should "proceed with caution"
	assert.NoError(t, err, "Should proceed with caution on SERVFAIL")
}

func TestCAAValidator_Validate_DNSNxdomain(t *testing.T) {
	mock := newMockDNSServer()
	mock.setRcode("nonexistent.example.com", dns.RcodeNameError)
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "nonexistent.example.com", false)
	assert.NoError(t, err, "Should allow issuance on NXDOMAIN (no CAA records)")
}

func TestCAAValidator_Validate_MultipleIdentities(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca2.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:   slog.Default(),
		Resolver: addr,
		Timeout:  2 * time.Second,
		CAAIdentities: []string{
			"ca1.example.com",
			"ca2.example.com",
			"ca3.example.com",
		},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should allow issuance when one of multiple identities matches")
}

func TestCAAValidator_Validate_CaseInsensitive(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("EXAMPLE.COM", "issue", "CA.EXAMPLE.COM")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should handle case-insensitive matching")
}

func TestCAAValidator_Cache(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// First validation - should query DNS
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err)

	// Check cache was populated
	cached := validator.getCached("example.com")
	assert.NotNil(t, cached, "Cache should be populated after first validation")
	assert.Len(t, cached, 1)

	// Second validation - should use cache
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err)

	// Clear cache
	validator.ClearCache()
	cached = validator.getCached("example.com")
	assert.Nil(t, cached, "Cache should be empty after clear")
}

func TestCAAValidator_CacheExpiration(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	// Override cache TTL for faster testing
	validator.cache.ttl = 100 * time.Millisecond

	ctx := context.Background()

	// First validation
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err)

	// Cache should be populated
	cached := validator.getCached("example.com")
	assert.NotNil(t, cached)

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Cache should be expired
	cached = validator.getCached("example.com")
	assert.Nil(t, cached, "Cache should expire after TTL")
}

func TestCAAValidator_EmptyValue(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Empty CAA value should deny issuance")
}

func TestCAAValidator_NoCAAIdentities(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: nil, // No identities configured
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	// Should allow issuance when no identities are configured
	assert.NoError(t, err, "Should allow issuance when no CAA identities configured")
}

func TestCAAValidator_ContextCancellation(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       10 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = validator.Validate(ctx, "example.com", false)
	// Should handle context cancellation gracefully
	// Note: Depending on timing, this might succeed or fail
	// The important thing is it doesn't panic
	t.Logf("Validation with cancelled context: %v", err)
}

func TestCAAValidator_Validate_MultipleRecordsOneDenies(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "other-ca.example.com")
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	// Should allow issuance if ANY CAA record matches
	assert.NoError(t, err, "Should allow issuance when at least one CAA record matches")
}

func TestCAARecord_IsAuthorized(t *testing.T) {
	validator := &CAAValidator{
		caaIdentities: []string{"ca.example.com", "ca2.example.net"},
	}

	tests := []struct {
		name       string
		value      string
		authorized bool
	}{
		{"exact match", "ca.example.com", true},
		{"exact match upper case", "CA.EXAMPLE.COM", true},
		{"no match", "other-ca.example.com", false},
		{"empty value", "", false},
		{"semicolon only", ";", false},
		{"second identity", "ca2.example.net", true},
		{"whitespace", "  ca.example.com  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isAuthorized(tt.value)
			assert.Equal(t, tt.authorized, result)
		})
	}
}

// Tests consolidated from caa_coverage_test.go

// TestCAAValidator_ValidateRecords_WildcardWithIssuewildNotAuthorized tests the issuewild not authorized path
func TestCAAValidator_ValidateRecords_WildcardWithIssuewildNotAuthorized(t *testing.T) {
	mock := newMockDNSServer()
	// Add issuewild record that doesn't match our identity
	mock.addCAARecord("example.com", "issuewild", "other-ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", true)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Should return CAA validation error for non-matching issuewild")
	assert.Contains(t, err.Error(), "no matching issuewild CAA record found")
}

// TestCAAValidator_ValidateRecords_OnlyIssuewildNoIssue tests wildcard with only issuewild, no issue records
func TestCAAValidator_ValidateRecords_OnlyIssuewildNoIssue(t *testing.T) {
	mock := newMockDNSServer()
	// Add only issuewild record with non-matching CA
	mock.addCAARecord("example.com", "issuewild", "another-ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", true)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Should deny wildcard when issuewild doesn't match")
}

// TestCAAValidator_ValidateRecords_NonWildcardWithIssuewildOnly tests non-wildcard validation
// when only issuewild records exist
func TestCAAValidator_ValidateRecords_NonWildcardWithIssuewildOnly(t *testing.T) {
	mock := newMockDNSServer()
	// Add only issuewild record - should be ignored for non-wildcard
	mock.addCAARecord("example.com", "issuewild", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// For non-wildcard, issuewild is ignored, so no relevant records found = allow
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should allow issuance when only issuewild exists for non-wildcard")
}

// TestCAAValidator_ValidateRecords_IssueNotAuthorized tests issue record that doesn't match
func TestCAAValidator_ValidateRecords_IssueNotAuthorized(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "different-ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Should deny when issue doesn't match")
	assert.Contains(t, err.Error(), "no matching issue CAA record found")
}

// TestCAAValidator_ValidateRecords_IssueWithSemicolon tests issue with semicolon value (deny all)
func TestCAAValidator_ValidateRecords_IssueWithSemicolon(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", ";")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)

	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Semicolon value should deny issuance")
}

// TestCAAValidator_ValidateRecords_OnlyIodef tests that iodef records are skipped
func TestCAAValidator_ValidateRecords_OnlyIodef(t *testing.T) {
	mock := newMockDNSServer()
	// Add only iodef record
	mock.addCAARecord("example.com", "iodef", "mailto:security@example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// No relevant CAA records (only iodef), so allow issuance
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should allow when only iodef records exist")
}

// TestCAAValidator_ValidateRecords_PrefixMatch tests that prefix matching works
func TestCAAValidator_ValidateRecords_PrefixMatch(t *testing.T) {
	mock := newMockDNSServer()
	// Add issue with extra parameters after domain
	mock.addCAARecord("example.com", "issue", "ca.example.com;policy=ev")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = validator.Validate(ctx, "example.com", false)
	assert.NoError(t, err, "Should allow when CAA value has matching prefix")
}

// TestCAAValidator_DNSError_OtherRcode tests handling of non-SERVFAIL/NXDOMAIN errors
func TestCAAValidator_DNSError_OtherRcode(t *testing.T) {
	mock := newMockDNSServer()
	mock.setRcode("example.com", dns.RcodeRefused)
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// DNS error during lookup should allow issuance (proceed with caution)
	err = validator.Validate(ctx, "example.com", false)
	// On error in lookupCAA, we return nil to allow issuance
	assert.NoError(t, err)
}

// TestErrCAAValidationFailed_Error tests error message formatting
func TestErrCAAValidationFailed_Error(t *testing.T) {
	err := &ErrCAAValidationFailed{
		Domain: "test.example.com",
		Reason: "no matching issue CAA record found",
	}
	expected := "CAA validation failed for test.example.com: no matching issue CAA record found"
	assert.Equal(t, expected, err.Error())
}

// TestErrCAADNSError_Error tests DNS error message formatting
func TestErrCAADNSError_Error(t *testing.T) {
	err := &ErrCAADNSError{
		Domain: "test.example.com",
		Err:    errors.New("connection refused"),
	}
	expected := "DNS error during CAA validation for test.example.com: connection refused"
	assert.Equal(t, expected, err.Error())
}

// TestCAAValidator_ValidateRecords_WildcardWithBothIssueAndIssuewildMatching tests
// wildcard where both issue and issuewild match
func TestCAAValidator_ValidateRecords_WildcardWithBothIssueAndIssuewildMatching(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	mock.addCAARecord("example.com", "issuewild", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Wildcard should be allowed because issuewild matches
	err = validator.Validate(ctx, "example.com", true)
	assert.NoError(t, err, "Wildcard should be allowed when issuewild matches")
}

// TestCAAValidator_ValidateRecords_WildcardNoIssuewildUseIssue tests wildcard fallback to issue
func TestCAAValidator_ValidateRecords_WildcardNoIssuewildUseIssue(t *testing.T) {
	mock := newMockDNSServer()
	// Only issue record, no issuewild
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Wildcard should fall back to issue when no issuewild
	err = validator.Validate(ctx, "example.com", true)
	assert.NoError(t, err, "Wildcard should use issue when no issuewild present")
}

// TestCAAValidator_ValidateRecords_WildcardNoIssuewildIssueNotMatch tests wildcard fallback to
// issue that doesn't match
func TestCAAValidator_ValidateRecords_WildcardNoIssuewildIssueNotMatch(t *testing.T) {
	mock := newMockDNSServer()
	// Only issue record that doesn't match
	mock.addCAARecord("example.com", "issue", "other-ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Wildcard should fail when issue doesn't match
	err = validator.Validate(ctx, "example.com", true)
	var caaErr *ErrCAAValidationFailed
	assert.True(t, errors.As(err, &caaErr), "Should deny wildcard when issue doesn't match")
}

// TestCAAValidator_Cache_SetAndGet tests cache functionality directly
func TestCAAValidator_Cache_SetAndGet(t *testing.T) {
	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      "127.0.0.1:53",
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	// Test setCached and getCached
	records := []*CAARecord{
		{Tag: "issue", Value: "ca.example.com", Flags: 0},
	}
	validator.setCached("test.example.com", records)

	cached := validator.getCached("test.example.com")
	require.NotNil(t, cached)
	assert.Len(t, cached, 1)
	assert.Equal(t, "issue", cached[0].Tag)

	// Test non-existent
	cached = validator.getCached("nonexistent.example.com")
	assert.Nil(t, cached)
}

// TestCAAValidator_Cache_ExpirationDirect tests cache TTL directly
func TestCAAValidator_Cache_ExpirationDirect(t *testing.T) {
	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      "127.0.0.1:53",
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	// Set short TTL
	validator.cache.ttl = 50 * time.Millisecond

	records := []*CAARecord{
		{Tag: "issue", Value: "ca.example.com", Flags: 0},
	}
	validator.setCached("expire.example.com", records)

	// Should exist immediately
	cached := validator.getCached("expire.example.com")
	assert.NotNil(t, cached)

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	cached = validator.getCached("expire.example.com")
	assert.Nil(t, cached)
}

// TestCAAValidator_IsAuthorized_EdgeCases tests edge cases for isAuthorized
func TestCAAValidator_IsAuthorized_EdgeCases(t *testing.T) {
	validator := &CAAValidator{
		caaIdentities: []string{"ca.example.com"},
	}

	tests := []struct {
		name       string
		value      string
		authorized bool
	}{
		{"empty string", "", false},
		{"semicolon", ";", false},
		{"exact match", "ca.example.com", true},
		{"uppercase match", "CA.EXAMPLE.COM", true},
		{"prefix with params", "ca.example.com;policy=ev", true},
		{"whitespace", "  ca.example.com  ", true},
		{"no match", "different.ca.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isAuthorized(tt.value)
			assert.Equal(t, tt.authorized, result)
		})
	}
}

// TestCAAValidator_Validate_DomainNormalization tests domain name normalization
func TestCAAValidator_Validate_DomainNormalization(t *testing.T) {
	mock := newMockDNSServer()
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Test with uppercase domain
	err = validator.Validate(ctx, "EXAMPLE.COM", false)
	assert.NoError(t, err)

	validator.ClearCache()

	// Test with trailing dot
	err = validator.Validate(ctx, "example.com.", false)
	assert.NoError(t, err)
}

// TestCAAValidator_CNAME_LookupError tests CNAME lookup error handling
func TestCAAValidator_CNAME_LookupError(t *testing.T) {
	mock := newMockDNSServer()
	// Set error for CNAME lookup
	mock.setRcode("alias.example.com", dns.RcodeServerFailure)
	mock.addCAARecord("example.com", "issue", "ca.example.com")
	addr := startMockDNSServer(t, mock)

	validator, err := NewCAAValidator(&CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      addr,
		Timeout:       2 * time.Second,
		CAAIdentities: []string{"ca.example.com"},
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Should handle CNAME error and continue with original domain
	err = validator.Validate(ctx, "alias.example.com", false)
	// SERVFAIL returns nil (proceed with caution)
	assert.NoError(t, err)
}
