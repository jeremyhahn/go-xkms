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
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testDNSServer creates a mock DNS server for testing
type testDNSServer struct {
	server       *dns.Server
	addr         string
	handler      dns.HandlerFunc
	responses    map[string][]dns.RR
	forceRcode   int         // Force a specific rcode for all queries
	silent       atomic.Bool // When set, accept the query and never reply
	mu           sync.RWMutex
	forceRcodeMu sync.RWMutex
}

func newTestDNSServer(t *testing.T) *testDNSServer {
	t.Helper()

	m := &testDNSServer{
		responses:  make(map[string][]dns.RR),
		forceRcode: -1, // -1 means don't force
	}

	// Find an available port
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	m.addr = listener.LocalAddr().String()

	m.handler = func(w dns.ResponseWriter, r *dns.Msg) {
		if m.silent.Load() {
			// Swallow the query so the caller reaches its context deadline
			// without a packet leaving the host.
			return
		}

		msg := new(dns.Msg)
		msg.SetReply(r)

		m.forceRcodeMu.RLock()
		forceRcode := m.forceRcode
		m.forceRcodeMu.RUnlock()

		if forceRcode >= 0 {
			msg.Rcode = forceRcode
			w.WriteMsg(msg)
			return
		}

		if len(r.Question) > 0 {
			q := r.Question[0]
			key := q.Name + dns.TypeToString[q.Qtype]

			m.mu.RLock()
			rrs, ok := m.responses[key]
			m.mu.RUnlock()

			if ok {
				msg.Answer = rrs
				msg.Rcode = dns.RcodeSuccess
			} else {
				msg.Rcode = dns.RcodeNameError
			}
		}

		w.WriteMsg(msg)
	}

	m.server = &dns.Server{
		PacketConn: listener,
		Handler:    m.handler,
	}

	go func() {
		_ = m.server.ActivateAndServe()
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	return m
}

// setSilent makes the server stop answering, which is how a test reaches the
// "nameserver did not respond" path without pointing at an address on the
// public internet and hoping nothing there replies.
func (m *testDNSServer) setSilent(silent bool) {
	m.silent.Store(silent)
}

func (m *testDNSServer) setForceRcode(rcode int) {
	m.forceRcodeMu.Lock()
	m.forceRcode = rcode
	m.forceRcodeMu.Unlock()
}

func (m *testDNSServer) addTXTRecord(fqdn, value string) {
	fqdn = ToFQDN(fqdn)
	key := fqdn + "TXT"
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Txt: []string{value},
	}
	m.mu.Lock()
	m.responses[key] = append(m.responses[key], txt)
	m.mu.Unlock()
}

// addSOARecord makes the server authoritative for a zone, which is what
// FindZoneByFQDN climbs the label tree looking for.
func (m *testDNSServer) addSOARecord(zone string) {
	zone = ToFQDN(zone)
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      "ns1." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	m.mu.Lock()
	m.responses[zone+"SOA"] = append(m.responses[zone+"SOA"], soa)
	m.mu.Unlock()
}

// addNSRecord publishes an NS record for a zone.
func (m *testDNSServer) addNSRecord(zone, nameserver string) {
	zone = ToFQDN(zone)
	ns := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: ToFQDN(nameserver),
	}
	m.mu.Lock()
	m.responses[zone+"NS"] = append(m.responses[zone+"NS"], ns)
	m.mu.Unlock()
}

// addARecord publishes an A record for a name.
func (m *testDNSServer) addARecord(fqdn string, ip net.IP) {
	fqdn = ToFQDN(fqdn)
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: ip,
	}
	m.mu.Lock()
	m.responses[fqdn+"A"] = append(m.responses[fqdn+"A"], a)
	m.mu.Unlock()
}

// addCNAMERecord publishes a CNAME record pointing fqdn at target.
func (m *testDNSServer) addCNAMERecord(fqdn, target string) {
	fqdn = ToFQDN(fqdn)
	cname := &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: ToFQDN(target),
	}
	m.mu.Lock()
	m.responses[fqdn+"CNAME"] = append(m.responses[fqdn+"CNAME"], cname)
	m.mu.Unlock()
}

// addEmptyAnswer makes the server answer NOERROR with no records for a name and
// type, the way a resolver reports "the name exists, this type does not".
// Without it an unregistered name answers NXDOMAIN, which is a different branch.
func (m *testDNSServer) addEmptyAnswer(fqdn string, qtype uint16) {
	fqdn = ToFQDN(fqdn)
	m.mu.Lock()
	m.responses[fqdn+dns.TypeToString[qtype]] = []dns.RR{}
	m.mu.Unlock()
}

// useAsDefaultResolver points DefaultNameservers at this server for the
// duration of the test, so nothing in the package reaches the public internet.
func (m *testDNSServer) useAsDefaultResolver(t *testing.T) {
	t.Helper()

	original := DefaultNameservers
	DefaultNameservers = []string{m.addr}
	t.Cleanup(func() { DefaultNameservers = original })
}

func (m *testDNSServer) close() {
	if m.server != nil {
		m.server.Shutdown()
	}
}

// closedDNSAddr returns a loopback address with nothing bound to it. A query
// sent there is refused immediately, which is how a test forces a nameserver
// failure without asking the host's resolver about a bogus hostname.
func closedDNSAddr(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a loopback port: %v", err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to release the reserved port: %v", err)
	}
	return addr
}

// truncatingDNSServer answers over UDP with the TC bit set and no records, and
// answers the same address over TCP with the full response. That is the
// exchange DNSQuery's UDP-to-TCP fallback exists for, and both transports are
// on loopback, so the fallback is exercised without a packet leaving the host.
type truncatingDNSServer struct {
	udp  *dns.Server
	tcp  *dns.Server
	addr string
}

func newTruncatingDNSServer(t *testing.T, answer dns.RR) *truncatingDNSServer {
	t.Helper()

	// The two transports must share a port number. Taking the TCP port first
	// and then binding UDP to it can lose a race against an unrelated socket,
	// so retry instead of failing the suite on it.
	var (
		listener net.Listener
		packets  net.PacketConn
		err      error
	)
	for attempt := 0; attempt < 10; attempt++ {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create tcp listener: %v", err)
		}

		packets, err = net.ListenPacket("udp", listener.Addr().String())
		if err == nil {
			break
		}

		if cerr := listener.Close(); cerr != nil {
			t.Fatalf("failed to close tcp listener: %v", cerr)
		}
	}
	if packets == nil {
		t.Fatalf("failed to bind udp and tcp to one loopback port: %v", err)
	}

	s := &truncatingDNSServer{addr: listener.Addr().String()}

	s.udp = &dns.Server{
		PacketConn: packets,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Truncated = true
			w.WriteMsg(msg)
		}),
	}

	s.tcp = &dns.Server{
		Listener: listener,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Answer = []dns.RR{answer}
			w.WriteMsg(msg)
		}),
	}

	go func() {
		_ = s.udp.ActivateAndServe()
	}()
	go func() {
		_ = s.tcp.ActivateAndServe()
	}()

	// Give both servers time to start
	time.Sleep(10 * time.Millisecond)

	return s
}

func (s *truncatingDNSServer) close() {
	if s.udp != nil {
		s.udp.Shutdown()
	}
	if s.tcp != nil {
		s.tcp.Shutdown()
	}
}

func TestPropagationChecker_NewPropagationChecker(t *testing.T) {
	t.Run("with custom nameservers", func(t *testing.T) {
		ns := []string{"1.1.1.1:53", "9.9.9.9:53"}
		checker := NewPropagationChecker(ns)
		if len(checker.nameservers) != 2 {
			t.Errorf("expected 2 nameservers, got %d", len(checker.nameservers))
		}
	})

	t.Run("with empty nameservers uses defaults", func(t *testing.T) {
		checker := NewPropagationChecker(nil)
		if len(checker.nameservers) != len(DefaultNameservers) {
			t.Errorf("expected %d nameservers, got %d", len(DefaultNameservers), len(checker.nameservers))
		}
	})
}

func TestPropagationCheckDNSPropagation(t *testing.T) {
	t.Run("successful propagation check", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("_acme-challenge.example.com", "test-token-value")

		ctx := context.Background()
		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com", "test-token-value", []string{server.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected record to be found")
		}
	})

	t.Run("record not found", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		ctx := context.Background()
		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com", "test-token-value", []string{server.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected record not to be found")
		}
	})

	t.Run("wrong value", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("_acme-challenge.example.com", "different-value")

		ctx := context.Background()
		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com", "test-token-value", []string{server.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected record not to match")
		}
	})

	t.Run("empty fqdn returns error", func(t *testing.T) {
		ctx := context.Background()
		_, err := CheckDNSPropagation(ctx, "", "value", []string{"8.8.8.8:53"})
		if err == nil {
			t.Error("expected error for empty fqdn")
		}
		var propErr *PropagationError
		if !errors.As(err, &propErr) {
			t.Error("expected PropagationError")
		}
	})

	t.Run("empty value returns error", func(t *testing.T) {
		ctx := context.Background()
		_, err := CheckDNSPropagation(ctx, "example.com", "", []string{"8.8.8.8:53"})
		if err == nil {
			t.Error("expected error for empty value")
		}
		var propErr *PropagationError
		if !errors.As(err, &propErr) {
			t.Error("expected PropagationError")
		}
	})

	t.Run("uses default nameservers when empty", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// This will likely fail with real DNS, but we're testing the default path
		_, _ = CheckDNSPropagation(ctx, "_acme-challenge.invalid-test-domain-xyz.com", "value", nil)
		// We just want to make sure it doesn't panic with nil nameservers
	})

	t.Run("partial propagation returns false", func(t *testing.T) {
		server1 := newTestDNSServer(t)
		defer server1.close()
		server2 := newTestDNSServer(t)
		defer server2.close()

		// Only add record to server1
		server1.addTXTRecord("_acme-challenge.example.com", "test-token")

		ctx := context.Background()
		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com", "test-token", []string{server1.addr, server2.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected partial propagation to return false")
		}
	})

	t.Run("full propagation across multiple servers", func(t *testing.T) {
		server1 := newTestDNSServer(t)
		defer server1.close()
		server2 := newTestDNSServer(t)
		defer server2.close()

		// Add record to both servers
		server1.addTXTRecord("_acme-challenge.example.com", "test-token")
		server2.addTXTRecord("_acme-challenge.example.com", "test-token")

		ctx := context.Background()
		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com", "test-token", []string{server1.addr, server2.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected full propagation to return true")
		}
	})

	t.Run("fqdn with trailing dot", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("_acme-challenge.example.com.", "test-token")

		ctx := context.Background()
		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com.", "test-token", []string{server.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected record to be found with trailing dot")
		}
	})

	t.Run("all nameservers fail returns error", func(t *testing.T) {
		// Create a server and close it immediately
		server := newTestDNSServer(t)
		server.close()

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		found, err := CheckDNSPropagation(ctx, "_acme-challenge.example.com", "test-token", []string{server.addr})
		if err == nil {
			t.Error("expected error when all nameservers fail")
		}
		if found {
			t.Error("should not return found when all nameservers fail")
		}
	})
}

func TestPropagationWaitForPropagation(t *testing.T) {
	t.Run("immediate propagation", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("_acme-challenge.example.com", "test-token")

		ctx := context.Background()
		err := WaitForPropagation(ctx, "_acme-challenge.example.com", "test-token", 5*time.Second, 100*time.Millisecond, []string{server.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("timeout when not propagated", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Don't add any records - should timeout

		ctx := context.Background()
		err := WaitForPropagation(ctx, "_acme-challenge.example.com", "test-token", 200*time.Millisecond, 50*time.Millisecond, []string{server.addr})
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if !errors.Is(err, ErrPropagationTimeout) {
			t.Errorf("expected ErrPropagationTimeout, got: %v", err)
		}
	})

	t.Run("already cancelled context returns immediately", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Create already-cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		err := WaitForPropagation(ctx, "_acme-challenge.example.com", "test-token", 10*time.Second, 50*time.Millisecond, []string{server.addr})
		elapsed := time.Since(start)

		// Should return quickly, not wait for the 10 second timeout
		if elapsed > time.Second {
			t.Errorf("took too long: %v", elapsed)
		}

		if err == nil {
			t.Fatal("expected error due to cancelled context")
		}
		// Either context.Canceled or ErrPropagationTimeout is acceptable
	})

	t.Run("empty fqdn returns error", func(t *testing.T) {
		ctx := context.Background()
		err := WaitForPropagation(ctx, "", "value", time.Second, 100*time.Millisecond, nil)
		if err == nil {
			t.Error("expected error for empty fqdn")
		}
		var propErr *PropagationError
		if !errors.As(err, &propErr) {
			t.Error("expected PropagationError")
		}
	})

	t.Run("empty value returns error", func(t *testing.T) {
		ctx := context.Background()
		err := WaitForPropagation(ctx, "example.com", "", time.Second, 100*time.Millisecond, nil)
		if err == nil {
			t.Error("expected error for empty value")
		}
		var propErr *PropagationError
		if !errors.As(err, &propErr) {
			t.Error("expected PropagationError")
		}
	})

	t.Run("uses default timeout and interval when zero", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("_acme-challenge.example.com", "test-token")

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		err := WaitForPropagation(ctx, "_acme-challenge.example.com", "test-token", 0, 0, []string{server.addr})
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("uses default nameservers when empty", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Will timeout but should use defaults
		_ = WaitForPropagation(ctx, "_acme-challenge.invalid-test.com", "value", 100*time.Millisecond, 50*time.Millisecond, nil)
	})

	t.Run("delayed propagation succeeds", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Add record after a delay
		go func() {
			time.Sleep(150 * time.Millisecond)
			server.addTXTRecord("_acme-challenge.delayed.com", "delayed-token")
		}()

		ctx := context.Background()
		err := WaitForPropagation(ctx, "_acme-challenge.delayed.com", "delayed-token", 2*time.Second, 50*time.Millisecond, []string{server.addr})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("wrong value never propagates", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Add a record with wrong value
		server.addTXTRecord("_acme-challenge.wrong.com", "wrong-value")

		ctx := context.Background()
		err := WaitForPropagation(ctx, "_acme-challenge.wrong.com", "correct-value", 200*time.Millisecond, 50*time.Millisecond, []string{server.addr})
		if err == nil {
			t.Fatal("expected timeout error for wrong value")
		}
		if !errors.Is(err, ErrPropagationTimeout) {
			t.Errorf("expected ErrPropagationTimeout, got: %v", err)
		}
	})
}

func TestPropagationGetAuthoritativeNameservers(t *testing.T) {
	t.Run("empty fqdn returns error", func(t *testing.T) {
		ctx := context.Background()
		_, err := GetAuthoritativeNameservers(ctx, "")
		if err == nil {
			t.Error("expected error for empty fqdn")
		}
		var propErr *PropagationError
		if !errors.As(err, &propErr) {
			t.Error("expected PropagationError")
		}
	})

	t.Run("authoritative nameservers are returned with a port", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		server.useAsDefaultResolver(t)

		const zone = "ns-lookup.test"
		server.addSOARecord(zone)
		server.addNSRecord(zone, "ns1."+zone)
		server.addNSRecord(zone, "ns2."+zone)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ns, err := GetAuthoritativeNameservers(ctx, zone)
		if err != nil {
			t.Fatalf("GetAuthoritativeNameservers: %v", err)
		}
		if len(ns) != 2 {
			t.Fatalf("expected 2 nameservers, got %d: %v", len(ns), ns)
		}
		// Callers feed these straight into DNSQuery, so each must carry a port.
		for _, n := range ns {
			if _, _, err := net.SplitHostPort(n); err != nil {
				t.Errorf("nameserver %s should have port: %v", n, err)
			}
		}
	})

	t.Run("invalid domain returns error", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		server.useAsDefaultResolver(t)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		_, err := GetAuthoritativeNameservers(ctx, "this-domain-definitely-does-not-exist-xyz123.invalid")
		if err == nil {
			t.Error("expected error for invalid domain")
		}
	})

	t.Run("fqdn is normalized with trailing dot", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()
		server.useAsDefaultResolver(t)

		const zone = "normalize.test"
		server.addSOARecord(zone)
		server.addNSRecord(zone, "ns1."+zone)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ns1, err1 := GetAuthoritativeNameservers(ctx, zone)
		if err1 != nil {
			t.Fatalf("GetAuthoritativeNameservers(%q): %v", zone, err1)
		}
		ns2, err2 := GetAuthoritativeNameservers(ctx, zone+".")
		if err2 != nil {
			t.Fatalf("GetAuthoritativeNameservers(%q.): %v", zone, err2)
		}

		// The trailing dot must not change the result at all.
		if !reflect.DeepEqual(ns1, ns2) {
			t.Errorf("trailing dot changed the result: %v vs %v", ns1, ns2)
		}
		if len(ns1) == 0 {
			t.Error("expected nameservers for both queries")
		}
	})
}

func TestPropagationError(t *testing.T) {
	t.Run("error with fqdn and message", func(t *testing.T) {
		err := &PropagationError{
			FQDN:    "example.com",
			Message: "test error",
		}
		expected := "propagation check for example.com: test error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("error with wrapped error", func(t *testing.T) {
		inner := errors.New("inner error")
		err := &PropagationError{
			FQDN:    "example.com",
			Message: "outer",
			Err:     inner,
		}
		if !errors.Is(err, inner) {
			t.Error("expected Unwrap to return inner error")
		}
		if err.Unwrap() != inner {
			t.Error("Unwrap() did not return inner error")
		}
		// Check the error message includes inner error
		expectedMsg := "propagation check for example.com: outer: inner error"
		if err.Error() != expectedMsg {
			t.Errorf("expected %q, got %q", expectedMsg, err.Error())
		}
	})

	t.Run("error without fqdn", func(t *testing.T) {
		err := &PropagationError{
			Message: "test error",
		}
		expected := "propagation check: test error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("error with all fields", func(t *testing.T) {
		inner := errors.New("wrapped")
		err := &PropagationError{
			FQDN:    "test.example.com",
			Message: "dns lookup failed",
			Err:     inner,
		}
		expected := "propagation check for test.example.com: dns lookup failed: wrapped"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}

func TestPropagation_checkTXTRecord(t *testing.T) {
	t.Run("successful txt lookup", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("_acme-challenge.test.com", "expected-value")

		ctx := context.Background()
		found, err := checkTXTRecord(ctx, ToFQDN("_acme-challenge.test.com"), "expected-value", server.addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected to find record")
		}
	})

	t.Run("nxdomain returns false", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		ctx := context.Background()
		found, err := checkTXTRecord(ctx, ToFQDN("nonexistent.test.com"), "value", server.addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected not found for NXDOMAIN")
		}
	})

	t.Run("multiple txt values", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Add multiple TXT records
		server.addTXTRecord("multi.test.com", "first-value")
		server.addTXTRecord("multi.test.com", "second-value")

		ctx := context.Background()
		found, err := checkTXTRecord(ctx, ToFQDN("multi.test.com"), "second-value", server.addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected to find second value")
		}
	})

	t.Run("first txt value found", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Add multiple TXT records
		server.addTXTRecord("multi.test.com", "first-value")
		server.addTXTRecord("multi.test.com", "second-value")

		ctx := context.Background()
		found, err := checkTXTRecord(ctx, ToFQDN("multi.test.com"), "first-value", server.addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found {
			t.Error("expected to find first value")
		}
	})

	t.Run("connection error", func(t *testing.T) {
		server := newTestDNSServer(t)
		server.close() // Close before query

		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		_, err := checkTXTRecord(ctx, ToFQDN("test.com"), "value", server.addr)
		if err == nil {
			t.Error("expected error for closed server")
		}
	})

	t.Run("value not in records", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		server.addTXTRecord("test.com", "other-value")

		ctx := context.Background()
		found, err := checkTXTRecord(ctx, ToFQDN("test.com"), "expected-value", server.addr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Error("expected not to find non-matching value")
		}
	})

	t.Run("non-success rcode returns error", func(t *testing.T) {
		server := newTestDNSServer(t)
		defer server.close()

		// Force server to return SERVFAIL
		server.setForceRcode(dns.RcodeServerFailure)

		ctx := context.Background()
		_, err := checkTXTRecord(ctx, ToFQDN("test.com"), "value", server.addr)
		if err == nil {
			t.Error("expected error for SERVFAIL rcode")
		}
	})
}
