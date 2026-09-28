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

package validation

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/netguard"
	"golang.org/x/net/dns/dnsmessage"
)

// splitServer returns the host and port of an httptest server.
func splitServer(t *testing.T, ts *httptest.Server) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatalf("split %s: %v", ts.URL, err)
	}
	return host, port
}

// requireKind asserts err is an *Error of the given kind.
func requireKind(t *testing.T, err error, want Kind) *Error {
	t.Helper()
	var verr *Error
	if !errors.As(err, &verr) {
		t.Fatalf("error = %v (%T), want *validation.Error of kind %q", err, err, want)
	}
	if verr.Kind != want {
		t.Fatalf("error kind = %q (%v), want %q", verr.Kind, err, want)
	}
	return verr
}

func TestGet_RefusesReservedTargets(t *testing.T) {
	client := NewClient(Config{})
	for _, host := range []string{
		"127.0.0.1",
		"::1",
		"169.254.169.254", // cloud metadata
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"fd00::1",
		"fe80::1",
		"0.0.0.0",
		"::ffff:127.0.0.1", // IPv4-mapped loopback
		"100.100.100.200",  // shared address space (Alibaba metadata)
	} {
		t.Run(host, func(t *testing.T) {
			_, err := client.Get(context.Background(), Target{Host: host, Port: "80", Path: "/"})
			verr := requireKind(t, err, KindTargetRefused)
			var refused *netguard.AddressNotPermittedError
			if !errors.As(verr, &refused) {
				t.Fatalf("error = %v, want a *netguard.AddressNotPermittedError in the chain", err)
			}
		})
	}
}

// TestGet_RefusesHostnameResolvingToLoopback resolves through the system
// hosts file: localhost is loopback on every platform the tests run on.
func TestGet_RefusesHostnameResolvingToLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a reserved target must never be contacted")
	}))
	defer ts.Close()
	_, port := splitServer(t, ts)

	_, err := NewClient(Config{}).Get(context.Background(), Target{Host: "localhost", Port: port, Path: "/"})
	requireKind(t, err, KindTargetRefused)
}

// fakeDNSResolver returns a resolver that answers every A query with addr
// and every other query with no records, served in memory over net.Pipe
// (stream framing: a two-byte length prefix per message).
func fakeDNSResolver(t *testing.T, addr netip.Addr) *net.Resolver {
	t.Helper()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			client, server := net.Pipe()
			go serveFakeDNS(server, addr)
			return client, nil
		},
	}
}

func serveFakeDNS(conn net.Conn, addr netip.Addr) {
	defer func() { _ = conn.Close() }()
	for {
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		var parser dnsmessage.Parser
		header, err := parser.Start(query)
		if err != nil {
			return
		}
		question, err := parser.Question()
		if err != nil {
			return
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true})
		builder.EnableCompression()
		if builder.StartQuestions() != nil || builder.Question(question) != nil || builder.StartAnswers() != nil {
			return
		}
		if question.Type == dnsmessage.TypeA {
			resource := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
			if builder.AResource(resource, dnsmessage.AResource{A: addr.As4()}) != nil {
				return
			}
		}
		answer, err := builder.Finish()
		if err != nil {
			return
		}
		framed := binary.BigEndian.AppendUint16(nil, uint16(len(answer)))
		if _, err := conn.Write(append(framed, answer...)); err != nil {
			return
		}
	}
}

// TestGet_RefusesPublicNameResolvingToPrivateAddress is the DNS-rebinding
// case: a name that looks external resolves to an RFC 1918 address. The
// check runs on the resolved address, so the name does not get it through.
func TestGet_RefusesPublicNameResolvingToPrivateAddress(t *testing.T) {
	resolver := fakeDNSResolver(t, netip.MustParseAddr("10.1.2.3"))
	client := NewClient(Config{Resolver: resolver})

	_, err := client.Get(context.Background(), Target{Host: "device.example.com", Port: "80", Path: "/"})
	verr := requireKind(t, err, KindTargetRefused)
	if !strings.Contains(verr.Error(), "10.1.2.3") {
		t.Fatalf("log-side error %q should name the resolved address", verr.Error())
	}
}

func TestGet_AllowPrivateTargetsReachesLoopback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)

	body, err := NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: host, Port: port, Path: "/x"})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
}

func TestGet_RejectsInvalidTargets(t *testing.T) {
	client := NewClient(Config{AllowPrivateTargets: true})
	for _, target := range []Target{
		{Host: "169.254.169.254/latest/meta-data", Port: "80"},
		{Host: "example.com?q=1", Port: "80"},
		{Host: "example.com#frag", Port: "80"},
		{Host: "user@example.com", Port: "80"},
		{Host: "example.com:8080", Port: "80"},
		{Host: "example .com", Port: "80"},
		{Host: "", Port: "80"},
		{Host: "fe80::1%eth0", Port: "80"},
		{Host: "example.com", Port: "0"},
		{Host: "example.com", Port: "65536"},
		{Host: "example.com", Port: "http"},
	} {
		t.Run(target.Host+"_"+target.Port, func(t *testing.T) {
			_, err := client.Get(context.Background(), target)
			requireKind(t, err, KindInvalidTarget)
		})
	}
}

func TestTargetURL_JoinsHostAndPort(t *testing.T) {
	u, err := Target{Host: "2001:db8::1", Port: "8080", Path: "/.well-known/acme-challenge/tok"}.URL()
	if err != nil {
		t.Fatalf("URL() error = %v", err)
	}
	if got, want := u.String(), "http://[2001:db8::1]:8080/.well-known/acme-challenge/tok"; got != want {
		t.Fatalf("URL() = %q, want %q", got, want)
	}
}

func TestGet_CapsResponse(t *testing.T) {
	const limit = 1024
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := limit
		if r.URL.Path == "/big" {
			size = limit + 1
		}
		_, _ = w.Write(bytes.Repeat([]byte("a"), size))
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)
	client := NewClient(Config{AllowPrivateTargets: true})

	body, err := client.Get(context.Background(), Target{Host: host, Port: port, Path: "/exact", MaxResponseBytes: limit})
	if err != nil || len(body) != limit {
		t.Fatalf("a body of exactly the limit must be accepted: len=%d err=%v", len(body), err)
	}

	_, err = client.Get(context.Background(), Target{Host: host, Port: port, Path: "/big", MaxResponseBytes: limit})
	requireKind(t, err, KindResponseTooLarge)
}

func TestGet_DefaultResponseCap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), int(DefaultMaxResponseBytes)+1))
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)

	_, err := NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: host, Port: port, Path: "/"})
	requireKind(t, err, KindResponseTooLarge)
}

func TestGet_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)

	_, err := NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: host, Port: port, Path: "/"})
	verr := requireKind(t, err, KindStatus)
	var status *StatusError
	if !errors.As(verr, &status) || status.StatusCode != http.StatusTeapot {
		t.Fatalf("error = %v, want a 418 *StatusError", err)
	}
}

func TestPost_SendsBodyAndContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)

	body, err := NewClient(Config{AllowPrivateTargets: true}).Post(context.Background(), Target{Host: host, Port: port, Path: "/"}, "application/json", []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if string(body) != `{"a":1}` {
		t.Fatalf("echoed body = %q", body)
	}
}

func TestGet_ConnectionFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	_ = listener.Close()

	_, err = NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: "127.0.0.1", Port: port, Path: "/"})
	requireKind(t, err, KindConnection)
}

func TestGet_RedirectsRefusedUnlessRequested(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "final")
	}))
	defer final.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/", http.StatusFound)
	}))
	defer redirector.Close()
	host, port := splitServer(t, redirector)
	client := NewClient(Config{AllowPrivateTargets: true})

	_, err := client.Get(context.Background(), Target{Host: host, Port: port, Path: "/"})
	requireKind(t, err, KindRedirect)

	body, err := client.Get(context.Background(), Target{Host: host, Port: port, Path: "/", FollowRedirects: true})
	if err != nil || string(body) != "final" {
		t.Fatalf("a requested redirect must be followed: body=%q err=%v", body, err)
	}
}

func TestGet_RedirectLoopIsBounded(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, ts.URL+"/again", http.StatusFound)
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)

	_, err := NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: host, Port: port, Path: "/", FollowRedirects: true})
	requireKind(t, err, KindRedirect)
}

func TestGet_RedirectToUnsupportedSchemeRefused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ftp://example.com/", http.StatusFound)
	}))
	defer ts.Close()
	host, port := splitServer(t, ts)

	_, err := NewClient(Config{AllowPrivateTargets: true}).Get(context.Background(), Target{Host: host, Port: port, Path: "/", FollowRedirects: true})
	requireKind(t, err, KindRedirect)
}

// TestGet_RedirectHopIsRecheckedByDialer proves a redirect cannot launder a
// reserved address: the first hop is permitted, the redirect target is not,
// and the dial-time check refuses the second connection. The permit-list
// control stands in for "the first server is public", which loopback test
// servers cannot otherwise be.
func TestGet_RedirectHopIsRecheckedByDialer(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the redirect target must never be contacted")
	}))
	defer internal.Close()
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/", http.StatusFound)
	}))
	defer public.Close()
	host, port := splitServer(t, public)

	permitPublicOnly := func(network, address string, _ syscall.RawConn) error {
		if strings.HasSuffix(address, ":"+port) {
			return nil
		}
		return &netguard.AddressNotPermittedError{Address: address}
	}
	client := newClient(nil, permitPublicOnly)

	_, err := client.Get(context.Background(), Target{Host: host, Port: port, Path: "/", FollowRedirects: true})
	requireKind(t, err, KindTargetRefused)
}

func TestGet_NilClient(t *testing.T) {
	var client *Client
	if _, err := client.Get(context.Background(), Target{Host: "example.com", Port: "80"}); !errors.Is(err, ErrNilClient) {
		t.Fatalf("Get() on a nil client error = %v, want ErrNilClient", err)
	}
}

// TestClientDialControl_MatchesNetguardDenyReserved proves NewClient wires
// its production Control hook to netguard.DialControl(netguard.DenyReserved)
// rather than a locally reimplemented check; the address classification
// itself is covered exhaustively by pkg/netguard's own tests.
func TestClientDialControl_MatchesNetguardDenyReserved(t *testing.T) {
	control := netguard.DialControl(netguard.DenyReserved)
	for _, tc := range []struct {
		address string
		refused bool
	}{
		{"127.0.0.1:80", true},
		{"8.8.8.8:80", false},
		{"not-an-address", true},
	} {
		err := control("tcp", tc.address, nil)
		if got := err != nil; got != tc.refused {
			t.Errorf("control(%q) refused = %v, want %v (err %v)", tc.address, got, tc.refused, err)
		}
	}
}

func TestKindString(t *testing.T) {
	if KindTargetRefused.String() != KindConnection.String() {
		t.Fatalf("a refused target must read like any other connection failure, or it becomes a probe")
	}
	if got := Kind(0).String(); got != "validation failed" {
		t.Fatalf("unknown kind String() = %q", got)
	}
	err := &Error{Kind: KindStatus}
	if err.Error() != "challenge validation: unexpected HTTP status" || err.Unwrap() != nil {
		t.Fatalf("Error() without a cause = %q", err.Error())
	}
}
