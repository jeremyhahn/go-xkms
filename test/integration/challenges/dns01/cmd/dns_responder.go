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

// Package main implements a mock DNS server for DNS-01 ACME challenge testing.
// It serves TXT records for _acme-challenge.<domain> queries.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	// txtRecords holds domain -> TXT record value mappings
	txtRecords = make(map[string]string)
	recordsMu  sync.RWMutex
)

func main() {
	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "53"
	}

	// Start DNS server
	dns.HandleFunc(".", handleDNSQuery)

	// Start HTTP API for setting TXT records
	go startHTTPAPI()

	server := &dns.Server{Addr: ":" + port, Net: "udp"}
	log.Printf("DNS-01 Mock DNS Server starting on UDP :%s", port)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DNS server failed: %v", err)
	}
}

func handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		log.Printf("DNS Query: Type=%s Name=%s", dns.TypeToString[q.Qtype], q.Name)

		switch q.Qtype {
		case dns.TypeTXT:
			handleTXTQuery(m, q)
		case dns.TypeA:
			handleAQuery(m, q)
		case dns.TypeAAAA:
			handleAAAAQuery(m, q)
		case dns.TypeSOA:
			handleSOAQuery(m, q)
		case dns.TypeNS:
			handleNSQuery(m, q)
		default:
			log.Printf("Unhandled query type: %s", dns.TypeToString[q.Qtype])
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

func handleTXTQuery(m *dns.Msg, q dns.Question) {
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	recordsMu.RLock()
	txtValue, exists := txtRecords[name]
	recordsMu.RUnlock()

	if exists {
		log.Printf("TXT record found for %s: %s", name, txtValue)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{txtValue},
		}
		m.Answer = append(m.Answer, rr)
	} else {
		log.Printf("TXT record not found for %s", name)
		m.Rcode = dns.RcodeNameError
	}
}

func handleAQuery(m *dns.Msg, q dns.Question) {
	// Return a default A record for test domains
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("127.0.0.1"),
	}
	m.Answer = append(m.Answer, rr)
}

func handleAAAAQuery(m *dns.Msg, q dns.Question) {
	// Return a default AAAA record for test domains
	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		AAAA: net.ParseIP("::1"),
	}
	m.Answer = append(m.Answer, rr)
}

func handleSOAQuery(m *dns.Msg, q dns.Question) {
	rr := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      "ns1.example.com.",
		Mbox:    "hostmaster.example.com.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
	m.Answer = append(m.Answer, rr)
}

func handleNSQuery(m *dns.Msg, q dns.Question) {
	rr := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: "ns1.example.com.",
	}
	m.Answer = append(m.Answer, rr)
}

func startHTTPAPI() {
	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8053"
	}

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/txt/set", setTXTHandler)
	http.HandleFunc("/txt/get", getTXTHandler)
	http.HandleFunc("/txt/delete", deleteTXTHandler)
	http.HandleFunc("/txt/list", listTXTHandler)

	log.Printf("DNS-01 HTTP API starting on :%s", port)
	server := &http.Server{
		Addr:              ":" + port,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("HTTP API server failed: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func setTXTHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	domain := r.FormValue("domain")
	value := r.FormValue("value")

	if domain == "" || value == "" {
		http.Error(w, "domain and value required", http.StatusBadRequest)
		return
	}

	domain = strings.ToLower(domain)

	recordsMu.Lock()
	txtRecords[domain] = value
	recordsMu.Unlock()

	log.Printf("TXT record set: %s = %s", domain, value)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "OK: %s = %s", domain, value)
}

func getTXTHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	domain = strings.ToLower(domain)

	recordsMu.RLock()
	value, exists := txtRecords[domain]
	recordsMu.RUnlock()

	if !exists {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(value))
}

func deleteTXTHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	domain := r.FormValue("domain")
	if domain == "" {
		http.Error(w, "domain required", http.StatusBadRequest)
		return
	}

	domain = strings.ToLower(domain)

	recordsMu.Lock()
	delete(txtRecords, domain)
	recordsMu.Unlock()

	log.Printf("TXT record deleted: %s", domain)
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "OK: deleted %s", domain)
}

func listTXTHandler(w http.ResponseWriter, r *http.Request) {
	recordsMu.RLock()
	defer recordsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, "{")
	first := true
	for domain, value := range txtRecords {
		if !first {
			_, _ = fmt.Fprintf(w, ",")
		}
		_, _ = fmt.Fprintf(w, "\"%s\":\"%s\"", domain, value)
		first = false
	}
	_, _ = fmt.Fprintf(w, "}")
}
