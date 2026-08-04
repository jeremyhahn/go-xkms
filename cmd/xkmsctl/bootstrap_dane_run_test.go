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

// bootstrap_dane_run_test.go exercises dnsResolver.LookupTLSA — the
// production miekg/dns TLSA resolver — against an in-process, localhost-only
// mock UDP DNS server, so the real DNS wire-protocol codepath is covered
// without any real network access.
package main

import (
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// startMockTLSADNSServer starts an in-process UDP DNS server bound to
// 127.0.0.1 that answers every TLSA query with the given records (or with
// a failure rcode when rcode != dns.RcodeSuccess). It returns the listen
// address and is torn down automatically via t.Cleanup.
func startMockTLSADNSServer(t *testing.T, records []dns.TLSA, rcode int) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = rcode
		if rcode == dns.RcodeSuccess {
			for _, q := range r.Question {
				if q.Qtype != dns.TypeTLSA {
					continue
				}
				for _, rec := range records {
					rr := rec
					rr.Hdr = dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTLSA,
						Class:  dns.ClassINET,
						Ttl:    300,
					}
					m.Answer = append(m.Answer, &rr)
				}
			}
		}
		if err := w.WriteMsg(m); err != nil {
			t.Logf("mock DNS: write response: %v", err)
		}
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	server := &dns.Server{PacketConn: pc, Handler: handler}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSResolver_LookupTLSA_Success(t *testing.T) {
	addr := startMockTLSADNSServer(t, []dns.TLSA{
		{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "ABCDEF0123"},
	}, dns.RcodeSuccess)

	r := &dnsResolver{}
	records, err := r.LookupTLSA("_443._tcp.kms.example.com", addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Usage != 3 || records[0].Selector != 1 || records[0].MatchingType != 1 {
		t.Errorf("unexpected record fields: %+v", records[0])
	}
	if records[0].Data != "abcdef0123" {
		t.Errorf("expected lowercased data, got %q", records[0].Data)
	}
}

func TestDNSResolver_LookupTLSA_NoRecords(t *testing.T) {
	addr := startMockTLSADNSServer(t, nil, dns.RcodeSuccess)

	r := &dnsResolver{}
	_, err := r.LookupTLSA("_443._tcp.kms.example.com", addr)
	if !errors.Is(err, ErrDNSNoRecords) {
		t.Fatalf("want ErrDNSNoRecords, got %v", err)
	}
}

func TestDNSResolver_LookupTLSA_ResponseCodeError(t *testing.T) {
	addr := startMockTLSADNSServer(t, nil, dns.RcodeNameError)

	r := &dnsResolver{}
	_, err := r.LookupTLSA("_443._tcp.nonexistent.example.com", addr)
	if !errors.Is(err, ErrDNSResponseCode) {
		t.Fatalf("want ErrDNSResponseCode, got %v", err)
	}
}

func TestDNSResolver_LookupTLSA_QueryError(t *testing.T) {
	// Port 0 on localhost with nothing listening: the exchange should fail
	// fast (connection refused) without any real network access.
	r := &dnsResolver{}
	_, err := r.LookupTLSA("_443._tcp.kms.example.com", "127.0.0.1:1")
	if !errors.Is(err, ErrDNSQuery) {
		t.Fatalf("want ErrDNSQuery, got %v", err)
	}
}
