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

package providers

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFindZoneByFQDNCacheExpired tests cache expiration handling.
func TestFindZoneByFQDNCacheExpired(t *testing.T) {
	// Clear cache first
	ClearZoneCache()

	// Add expired cache entry
	zoneCacheMu.Lock()
	zoneCache["_acme-challenge.expired-domain.com."] = zoneCacheEntry{
		zone:       "expired-domain.com.",
		expiryTime: time.Now().Add(-time.Hour), // Expired
	}
	zoneCacheMu.Unlock()

	ctx := context.Background()

	// This should miss the cache due to expiration and try a DNS lookup, which
	// fails against a loopback address with nothing bound to it — no name to
	// resolve and no packet off the host.
	_, err := FindZoneByFQDN(ctx, "_acme-challenge.expired-domain.com.", []string{closedDNSAddr(t)})
	require.Error(t, err)

	// Clean up
	ClearZoneCache()
}

// TestDNSQueryWithNameserverWithoutPort tests nameserver port handling.
//
// The context is cancelled before the call, so the dial fails before a packet
// is sent and the address it reports is exactly the one DNSQuery assembled.
func TestDNSQueryWithNameserverWithoutPort(t *testing.T) {
	tests := []struct {
		name       string
		nameserver string
		wantAddr   string
	}{
		{
			name:       "bare address gets the default port",
			nameserver: "127.0.0.1",
			wantAddr:   "127.0.0.1:53",
		},
		{
			name:       "address with a port keeps it",
			nameserver: "127.0.0.1:5353",
			wantAddr:   "127.0.0.1:5353",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := DNSQuery(ctx, "example.com.", dns.TypeSOA, []string{tt.nameserver}, true)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantAddr)
		})
	}
}

// TestDNSQueryUDPTruncation tests TCP fallback on UDP truncation.
func TestDNSQueryUDPTruncation(t *testing.T) {
	answer := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   "truncated.example.com.",
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: []string{"only-over-tcp"},
	}

	server := newTruncatingDNSServer(t, answer)
	defer server.close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := DNSQuery(ctx, "truncated.example.com.", dns.TypeTXT, []string{server.addr}, true)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// The UDP reply carried the TC bit and no records, so an answer here can
	// only have come from the TCP retry.
	assert.False(t, resp.Truncated)
	require.Len(t, resp.Answer, 1)
	txt, ok := resp.Answer[0].(*dns.TXT)
	require.True(t, ok, "expected a TXT record, got %T", resp.Answer[0])
	assert.Equal(t, []string{"only-over-tcp"}, txt.Txt)
}

// TestWaitForCtxContextCancellation tests WaitForCtx with context cancellation.
func TestWaitForCtxContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := WaitForCtx(ctx, time.Second, 10*time.Millisecond, func() (bool, error) {
		return false, nil
	})
	require.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

// TestRegisterEnvFactoryAndGet tests env factory registration and retrieval.
func TestRegisterEnvFactoryAndGet(t *testing.T) {
	// Register a test env factory
	testFactory := func(ctx context.Context) (Provider, error) {
		return nil, errors.New("test factory")
	}

	RegisterEnvFactory("test-env-provider", testFactory)

	// Retrieve it
	factory := GetEnvFactory("test-env-provider")
	require.NotNil(t, factory)

	// Verify it works
	_, err := factory(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test factory")

	// Non-existent factory returns nil
	factory = GetEnvFactory("nonexistent-provider")
	assert.Nil(t, factory)
}

// TestContainsCNAMEFunction tests the containsCNAME helper function.
func TestContainsCNAMEFunction(t *testing.T) {
	t.Run("returns true when CNAME exists", func(t *testing.T) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: "alias.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "target.example.com.",
		})

		assert.True(t, containsCNAME(msg))
	})

	t.Run("returns false when no CNAME exists", func(t *testing.T) {
		msg := &dns.Msg{}
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{1, 2, 3, 4},
		})

		assert.False(t, containsCNAME(msg))
	})

	t.Run("returns false for empty message", func(t *testing.T) {
		msg := &dns.Msg{}
		assert.False(t, containsCNAME(msg))
	})
}

// TestGetNameserversFromConfigWithServers tests reading actual nameservers.
//
// The fixture is written by the test rather than read from /etc/resolv.conf:
// the host may have no resolver configured, and if it has one its contents are
// not this test's subject.
func TestGetNameserversFromConfigWithServers(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "resolv.conf")
	err := os.WriteFile(configPath, []byte("nameserver 127.0.0.1\nnameserver 127.0.0.2\n"), 0o600)
	require.NoError(t, err)

	servers := GetNameserversFromConfig(configPath)
	assert.Equal(t, []string{"127.0.0.1:53", "127.0.0.2:53"}, servers)
}

// TestDNSQueryWithMultipleNameservers tests DNS query with multiple nameservers.
func TestDNSQueryWithMultipleNameservers(t *testing.T) {
	server := newTestDNSServer(t)
	defer server.close()
	server.addARecord("multi.example.com.", net.IPv4(203, 0, 113, 5))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The first nameserver refuses the query, so a result proves DNSQuery moved
	// on to the second rather than giving up on the first failure.
	resp, err := DNSQuery(ctx, "multi.example.com.", dns.TypeA, []string{
		closedDNSAddr(t),
		server.addr,
	}, true)
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)
	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok, "expected an A record, got %T", resp.Answer[0])
	assert.Equal(t, "203.0.113.5", a.A.String())
}

// TestDNSQueryNoNameserversResponded tests handling when no nameservers respond.
func TestDNSQueryNoNameserversResponded(t *testing.T) {
	t.Run("nameserver accepts the query and never answers", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		server.setSilent(true)

		// The deadline is the whole point of the case: the server holds the
		// query, so the query can only end when the context expires.
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()

		_, err := DNSQuery(ctx, "example.com.", dns.TypeA, []string{server.addr}, true)
		require.Error(t, err)
	})

	t.Run("no nameservers to query", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// With nothing to iterate there is no underlying error to report, which
		// is the only way to reach the "no nameservers responded" message.
		_, err := DNSQuery(ctx, "example.com.", dns.TypeA, nil, true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no nameservers responded")
	})
}

// TestFollowCNAMEs tests the FollowCNAMEs function.
func TestFollowCNAMEs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("returns original fqdn when no CNAME exists", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		// NOERROR with no CNAME record, which is what a name that exists but
		// is not an alias answers.
		server.addEmptyAnswer("example.com.", dns.TypeCNAME)

		result, err := FollowCNAMEs(ctx, "example.com.", []string{server.addr})
		require.NoError(t, err)
		assert.Equal(t, "example.com.", result)
	})

	t.Run("uses default nameservers when none provided", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		server.useAsDefaultResolver(t)
		server.addCNAMERecord("alias.example.com.", "target.example.com.")
		server.addEmptyAnswer("target.example.com.", dns.TypeCNAME)

		result, err := FollowCNAMEs(ctx, "alias.example.com.", nil)
		require.NoError(t, err)
		assert.Equal(t, "target.example.com.", result)
	})

	t.Run("returns error when DNS query fails", func(t *testing.T) {
		// Nothing is bound to this address, so the query is refused.
		_, err := FollowCNAMEs(ctx, "example.com.", []string{closedDNSAddr(t)})
		require.Error(t, err)
	})

	t.Run("detects a CNAME loop", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		server.addCNAMERecord("first.example.com.", "second.example.com.")
		server.addCNAMERecord("second.example.com.", "first.example.com.")

		_, err := FollowCNAMEs(ctx, "first.example.com.", []string{server.addr})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CNAME loop detected")
	})
}

// TestFollowCNAMEsWithRealCNAME tests following a chain of CNAME records to its
// final target.
func TestFollowCNAMEsWithRealCNAME(t *testing.T) {
	server := newTestDNSServer(t)
	defer server.close()
	server.addCNAMERecord("www.example.com.", "cdn.example.com.")
	server.addCNAMERecord("cdn.example.com.", "edge.example.com.")
	server.addEmptyAnswer("edge.example.com.", dns.TypeCNAME)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := FollowCNAMEs(ctx, "www.example.com.", []string{server.addr})
	require.NoError(t, err)
	assert.Equal(t, "edge.example.com.", result)
}
