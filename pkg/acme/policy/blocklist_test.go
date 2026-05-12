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

package policy

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestNewBlocklist(t *testing.T) {
	bl := NewBlocklist()
	if bl == nil {
		t.Fatal("NewBlocklist() returned nil")
	}
	if bl.domainBlocklist == nil {
		t.Error("domainBlocklist should be initialized")
	}
	if bl.fqdnBlocklist == nil {
		t.Error("fqdnBlocklist should be initialized")
	}
	if bl.wildcardFqdnBlocklist == nil {
		t.Error("wildcardFqdnBlocklist should be initialized")
	}
	if bl.ipPrefixBlocklist == nil {
		t.Error("ipPrefixBlocklist should be initialized")
	}
	if bl.IsLoaded() {
		t.Error("IsLoaded() should return false for new blocklist")
	}
}

func TestNewBlocklistWithLogger(t *testing.T) {
	logger := slog.Default()
	bl := NewBlocklistWithLogger(logger)
	if bl == nil {
		t.Fatal("NewBlocklistWithLogger() returned nil")
	}
	if bl.logger != logger {
		t.Error("logger should be set to provided logger")
	}

	// Test with nil logger
	bl2 := NewBlocklistWithLogger(nil)
	if bl2.logger == nil {
		t.Error("logger should default to slog.Default() when nil")
	}
}

func TestBlocklist_LoadFromConfig(t *testing.T) {
	bl := NewBlocklist()

	config := &BlocklistConfig{
		HighRiskBlockedNames: []string{"example.com", "malicious.net"},
		ExactBlockedNames:    []string{"specific.host.com", "another.host.org"},
		AdminBlockedNames:    []string{"admin-blocked.com"},
		AdminBlockedPrefixes: []string{"192.168.0.0/16", "10.0.0.0/8"},
	}

	err := bl.LoadFromConfig(config)
	if err != nil {
		t.Fatalf("LoadFromConfig() error = %v", err)
	}

	if !bl.IsLoaded() {
		t.Error("IsLoaded() should return true after loading config")
	}

	// Verify stats
	stats := bl.Stats()
	if stats.DomainEntries != 3 { // high-risk + admin
		t.Errorf("DomainEntries = %d, want 3", stats.DomainEntries)
	}
	if stats.FQDNEntries != 2 {
		t.Errorf("FQDNEntries = %d, want 2", stats.FQDNEntries)
	}
	if stats.WildcardFQDNEntries != 2 { // parent domains of exact entries
		t.Errorf("WildcardFQDNEntries = %d, want 2", stats.WildcardFQDNEntries)
	}
	if stats.IPPrefixEntries != 2 {
		t.Errorf("IPPrefixEntries = %d, want 2", stats.IPPrefixEntries)
	}
}

func TestBlocklist_LoadFromConfig_NilConfig(t *testing.T) {
	bl := NewBlocklist()
	err := bl.LoadFromConfig(nil)
	if err == nil {
		t.Error("LoadFromConfig(nil) should return error")
	}
	if !errors.Is(err, ErrBlocklistFileParse) {
		t.Errorf("error should wrap ErrBlocklistFileParse, got %v", err)
	}
}

func TestBlocklist_LoadFromConfig_MalformedExactEntry(t *testing.T) {
	bl := NewBlocklist()

	config := &BlocklistConfig{
		ExactBlockedNames: []string{"singlelabel"}, // No dots - malformed
	}

	err := bl.LoadFromConfig(config)
	if err == nil {
		t.Error("LoadFromConfig() with malformed entry should return error")
	}
	if !errors.Is(err, ErrMalformedBlocklistEntry) {
		t.Errorf("error should wrap ErrMalformedBlocklistEntry, got %v", err)
	}
}

func TestBlocklist_LoadFromConfig_MalformedIPPrefix(t *testing.T) {
	bl := NewBlocklist()

	config := &BlocklistConfig{
		AdminBlockedPrefixes: []string{"not-a-prefix"},
	}

	err := bl.LoadFromConfig(config)
	if err == nil {
		t.Error("LoadFromConfig() with malformed IP prefix should return error")
	}
	if !errors.Is(err, ErrMalformedIPPrefix) {
		t.Errorf("error should wrap ErrMalformedIPPrefix, got %v", err)
	}
}

func TestBlocklist_LoadFromFile(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "blocklist.yaml")

	// Write test config
	configContent := `
highRiskBlockedNames:
  - example.com
  - malicious.net
exactBlockedNames:
  - specific.host.com
adminBlockedPrefixes:
  - 192.168.0.0/16
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	bl := NewBlocklist()
	err = bl.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if !bl.IsLoaded() {
		t.Error("IsLoaded() should return true after loading file")
	}

	// Verify domain is blocked
	blocked, _ := bl.IsDomainBlocked("example.com")
	if !blocked {
		t.Error("example.com should be blocked")
	}
}

func TestBlocklist_LoadFromFile_NotFound(t *testing.T) {
	bl := NewBlocklist()
	err := bl.LoadFromFile("/nonexistent/path/blocklist.yaml")
	if err == nil {
		t.Error("LoadFromFile() with nonexistent file should return error")
	}
	if !errors.Is(err, ErrBlocklistFileRead) {
		t.Errorf("error should wrap ErrBlocklistFileRead, got %v", err)
	}
}

func TestBlocklist_LoadFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Write invalid YAML
	err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644)
	if err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	bl := NewBlocklist()
	err = bl.LoadFromFile(configPath)
	if err == nil {
		t.Error("LoadFromFile() with invalid YAML should return error")
	}
	if !errors.Is(err, ErrBlocklistFileParse) {
		t.Errorf("error should wrap ErrBlocklistFileParse, got %v", err)
	}
}

func TestBlocklist_IsDomainBlocked(t *testing.T) {
	bl := NewBlocklist()
	config := &BlocklistConfig{
		HighRiskBlockedNames: []string{"blocked.com", "malicious.net"},
		ExactBlockedNames:    []string{"specific.allowed.org"},
	}
	_ = bl.LoadFromConfig(config)

	tests := []struct {
		domain  string
		blocked bool
		reason  string
	}{
		{"blocked.com", true, "domain matches high-risk blocklist pattern"},
		{"www.blocked.com", true, "domain matches high-risk blocklist pattern"},
		{"sub.www.blocked.com", true, "domain matches high-risk blocklist pattern"},
		{"malicious.net", true, "domain matches high-risk blocklist pattern"},
		{"specific.allowed.org", true, "domain is in the exact FQDN blocklist"},
		{"other.allowed.org", false, ""},
		{"allowed.org", false, ""},
		{"notblocked.com", false, ""},
		// Case insensitivity
		{"BLOCKED.COM", true, "domain matches high-risk blocklist pattern"},
		{"Blocked.Com", true, "domain matches high-risk blocklist pattern"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			blocked, reason := bl.IsDomainBlocked(tt.domain)
			if blocked != tt.blocked {
				t.Errorf("IsDomainBlocked(%q) blocked = %v, want %v", tt.domain, blocked, tt.blocked)
			}
			if tt.blocked && reason == "" {
				t.Errorf("IsDomainBlocked(%q) reason should not be empty when blocked", tt.domain)
			}
		})
	}
}

func TestBlocklist_IsDomainBlocked_NotLoaded(t *testing.T) {
	bl := NewBlocklist()
	blocked, _ := bl.IsDomainBlocked("example.com")
	if blocked {
		t.Error("IsDomainBlocked() should return false when policy not loaded")
	}
}

func TestBlocklist_IsDomainBlocked_Wildcard(t *testing.T) {
	bl := NewBlocklist()
	config := &BlocklistConfig{
		HighRiskBlockedNames: []string{"blocked.com"},
	}
	_ = bl.LoadFromConfig(config)

	// Wildcard prefix should be stripped for checking
	blocked, _ := bl.IsDomainBlocked("*.blocked.com")
	if !blocked {
		t.Error("*.blocked.com should be blocked")
	}

	blocked, _ = bl.IsDomainBlocked("*.notblocked.com")
	if blocked {
		t.Error("*.notblocked.com should not be blocked")
	}
}

func TestBlocklist_IsIPBlocked(t *testing.T) {
	bl := NewBlocklist()
	config := &BlocklistConfig{
		AdminBlockedPrefixes: []string{
			"192.168.0.0/16",
			"10.0.0.0/8",
			"2001:db8::/32",
		},
	}
	_ = bl.LoadFromConfig(config)

	tests := []struct {
		ip      string
		blocked bool
	}{
		{"192.168.1.1", true},
		{"192.168.255.255", true},
		{"10.1.2.3", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"2001:db8::1", true},
		{"2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			blocked, reason := bl.IsIPBlocked(ip)
			if blocked != tt.blocked {
				t.Errorf("IsIPBlocked(%q) = %v, want %v", tt.ip, blocked, tt.blocked)
			}
			if tt.blocked && reason == "" {
				t.Errorf("IsIPBlocked(%q) reason should not be empty when blocked", tt.ip)
			}
		})
	}
}

func TestBlocklist_IsIPBlocked_NotLoaded(t *testing.T) {
	bl := NewBlocklist()
	ip := netip.MustParseAddr("192.168.1.1")
	blocked, _ := bl.IsIPBlocked(ip)
	if blocked {
		t.Error("IsIPBlocked() should return false when policy not loaded")
	}
}

func TestBlocklist_IsIPBlocked_WithZone(t *testing.T) {
	bl := NewBlocklist()
	config := &BlocklistConfig{
		AdminBlockedPrefixes: []string{"fe80::/10"},
	}
	_ = bl.LoadFromConfig(config)

	// IP with zone should still be checked after zone is stripped
	ip := netip.MustParseAddr("fe80::1")
	ip = ip.WithZone("eth0")

	blocked, _ := bl.IsIPBlocked(ip)
	if !blocked {
		t.Error("IP with zone should still be blocked")
	}
}

func TestBlocklist_IsWildcardBlocked(t *testing.T) {
	bl := NewBlocklist()
	config := &BlocklistConfig{
		HighRiskBlockedNames: []string{"blocked.com"},
		ExactBlockedNames:    []string{"specific.allowed.org"},
	}
	_ = bl.LoadFromConfig(config)

	tests := []struct {
		domain  string
		blocked bool
	}{
		// Wildcard for high-risk domain should be blocked
		{"blocked.com", true},
		{"sub.blocked.com", true},
		// Parent of exact blocked name should be in wildcard blocklist
		{"allowed.org", true}, // Because specific.allowed.org is exact blocked
		// Not blocked
		{"notblocked.com", false},
		{"other.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			blocked, reason := bl.IsWildcardBlocked(tt.domain)
			if blocked != tt.blocked {
				t.Errorf("IsWildcardBlocked(%q) = %v, want %v", tt.domain, blocked, tt.blocked)
			}
			if tt.blocked && reason == "" {
				t.Errorf("IsWildcardBlocked(%q) reason should not be empty when blocked", tt.domain)
			}
		})
	}
}

func TestBlocklist_IsWildcardBlocked_NotLoaded(t *testing.T) {
	bl := NewBlocklist()
	blocked, _ := bl.IsWildcardBlocked("example.com")
	if blocked {
		t.Error("IsWildcardBlocked() should return false when policy not loaded")
	}
}

func TestBlocklist_CheckIdentifier(t *testing.T) {
	bl := NewBlocklist()
	config := &BlocklistConfig{
		HighRiskBlockedNames: []string{"blocked.com"},
		AdminBlockedPrefixes: []string{"192.168.0.0/16"},
	}
	_ = bl.LoadFromConfig(config)

	tests := []struct {
		idType  string
		value   string
		wantErr bool
	}{
		// DNS checks
		{IdentifierTypeDNS, "blocked.com", true},
		{IdentifierTypeDNS, "www.blocked.com", true},
		{IdentifierTypeDNS, "*.blocked.com", true},
		{IdentifierTypeDNS, "allowed.com", false},
		// IP checks
		{IdentifierTypeIP, "192.168.1.1", true},
		{IdentifierTypeIP, "8.8.8.8", false},
		{IdentifierTypeIP, "invalid-ip", true}, // Invalid IP
		// Unsupported type
		{"unknown", "value", true},
	}

	for _, tt := range tests {
		t.Run(tt.idType+"_"+tt.value, func(t *testing.T) {
			err := bl.CheckIdentifier(tt.idType, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckIdentifier(%q, %q) error = %v, wantErr %v",
					tt.idType, tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestBlocklist_CheckIdentifier_NotLoaded(t *testing.T) {
	bl := NewBlocklist()
	err := bl.CheckIdentifier(IdentifierTypeDNS, "example.com")
	if !errors.Is(err, ErrPolicyNotLoaded) {
		t.Errorf("CheckIdentifier() should return ErrPolicyNotLoaded, got %v", err)
	}
}

func TestBlocklist_AddDomainBlock(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{})

	bl.AddDomainBlock("newblocked.com")

	blocked, _ := bl.IsDomainBlocked("newblocked.com")
	if !blocked {
		t.Error("AddDomainBlock() should add domain to blocklist")
	}

	// Case insensitivity
	blocked, _ = bl.IsDomainBlocked("NEWBLOCKED.COM")
	if !blocked {
		t.Error("AddDomainBlock() should be case insensitive")
	}
}

func TestBlocklist_AddFQDNBlock(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{})

	bl.AddFQDNBlock("specific.newblocked.com")

	// FQDN should be blocked
	blocked, _ := bl.IsDomainBlocked("specific.newblocked.com")
	if !blocked {
		t.Error("AddFQDNBlock() should add FQDN to blocklist")
	}

	// Parent should be in wildcard blocklist
	blocked, _ = bl.IsWildcardBlocked("newblocked.com")
	if !blocked {
		t.Error("AddFQDNBlock() should add parent to wildcard blocklist")
	}

	// Other subdomains should not be blocked
	blocked, _ = bl.IsDomainBlocked("other.newblocked.com")
	if blocked {
		t.Error("AddFQDNBlock() should not block other subdomains")
	}
}

func TestBlocklist_AddIPPrefixBlock(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{})

	prefix := netip.MustParsePrefix("172.16.0.0/12")
	bl.AddIPPrefixBlock(prefix)

	ip := netip.MustParseAddr("172.16.1.1")
	blocked, _ := bl.IsIPBlocked(ip)
	if !blocked {
		t.Error("AddIPPrefixBlock() should add prefix to blocklist")
	}
}

func TestBlocklist_RemoveDomainBlock(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{
		HighRiskBlockedNames: []string{"toremove.com"},
	})

	// Verify initially blocked
	blocked, _ := bl.IsDomainBlocked("toremove.com")
	if !blocked {
		t.Fatal("toremove.com should be initially blocked")
	}

	bl.RemoveDomainBlock("toremove.com")

	blocked, _ = bl.IsDomainBlocked("toremove.com")
	if blocked {
		t.Error("RemoveDomainBlock() should remove domain from blocklist")
	}
}

func TestBlocklist_RemoveFQDNBlock(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{
		ExactBlockedNames: []string{"toremove.example.com"},
	})

	bl.RemoveFQDNBlock("toremove.example.com")

	blocked, _ := bl.IsDomainBlocked("toremove.example.com")
	if blocked {
		t.Error("RemoveFQDNBlock() should remove FQDN from blocklist")
	}
}

func TestBlocklist_Clear(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{
		HighRiskBlockedNames: []string{"blocked.com"},
		ExactBlockedNames:    []string{"exact.blocked.com"},
		AdminBlockedPrefixes: []string{"10.0.0.0/8"},
	})

	bl.Clear()

	// Should not block anything after clear
	blocked, _ := bl.IsDomainBlocked("blocked.com")
	if blocked {
		t.Error("Clear() should remove all domain entries")
	}

	ip := netip.MustParseAddr("10.1.1.1")
	blocked, _ = bl.IsIPBlocked(ip)
	if blocked {
		t.Error("Clear() should remove all IP entries")
	}

	stats := bl.Stats()
	if stats.DomainEntries != 0 || stats.FQDNEntries != 0 ||
		stats.WildcardFQDNEntries != 0 || stats.IPPrefixEntries != 0 {
		t.Error("Clear() should result in zero entries")
	}
}

func TestBlocklist_Stats(t *testing.T) {
	bl := NewBlocklist()

	// Stats before loading
	stats := bl.Stats()
	if stats.Loaded {
		t.Error("Loaded should be false before loading config")
	}

	_ = bl.LoadFromConfig(&BlocklistConfig{
		HighRiskBlockedNames: []string{"a.com", "b.com"},
		ExactBlockedNames:    []string{"x.y.com"},
		AdminBlockedNames:    []string{"c.com"},
		AdminBlockedPrefixes: []string{"10.0.0.0/8", "192.168.0.0/16"},
	})

	stats = bl.Stats()
	if !stats.Loaded {
		t.Error("Loaded should be true after loading config")
	}
	if stats.DomainEntries != 3 { // high-risk + admin
		t.Errorf("DomainEntries = %d, want 3", stats.DomainEntries)
	}
	if stats.FQDNEntries != 1 {
		t.Errorf("FQDNEntries = %d, want 1", stats.FQDNEntries)
	}
	if stats.WildcardFQDNEntries != 1 { // parent of x.y.com
		t.Errorf("WildcardFQDNEntries = %d, want 1", stats.WildcardFQDNEntries)
	}
	if stats.IPPrefixEntries != 2 {
		t.Errorf("IPPrefixEntries = %d, want 2", stats.IPPrefixEntries)
	}
}

func TestBlocklist_ConcurrentAccess(t *testing.T) {
	bl := NewBlocklist()
	_ = bl.LoadFromConfig(&BlocklistConfig{
		HighRiskBlockedNames: []string{"blocked.com"},
		AdminBlockedPrefixes: []string{"192.168.0.0/16"},
	})

	// Run concurrent reads and writes
	done := make(chan bool)

	// Reader goroutines
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				bl.IsDomainBlocked("blocked.com")
				bl.IsIPBlocked(netip.MustParseAddr("192.168.1.1"))
				bl.IsWildcardBlocked("blocked.com")
				bl.Stats()
			}
			done <- true
		}()
	}

	// Writer goroutines
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 50; j++ {
				bl.AddDomainBlock("newdomain" + string(rune('0'+id)) + ".com")
				bl.RemoveDomainBlock("newdomain" + string(rune('0'+id)) + ".com")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}
}
