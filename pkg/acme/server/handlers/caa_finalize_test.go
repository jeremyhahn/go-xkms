//go:build codec_json

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

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	acmeserver "github.com/jeremyhahn/go-xkms/pkg/acme/server"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caaFinalizeMockDNS is a minimal authoritative DNS stub that answers CAA
// and CNAME queries from an in-memory record set, exercising the real
// server.CAAValidator (not a hand-rolled test double) through
// OrderFinalizeHandler. It mirrors pkg/acme/server's own mock DNS server;
// it cannot be reused directly because that one is unexported in a
// different package.
type caaFinalizeMockDNS struct {
	caaRecords map[string][]*dns.CAA
	rcode      map[string]int
}

func newCAAFinalizeMockDNS() *caaFinalizeMockDNS {
	return &caaFinalizeMockDNS{
		caaRecords: make(map[string][]*dns.CAA),
		rcode:      make(map[string]int),
	}
}

func (m *caaFinalizeMockDNS) addCAARecord(domain, tag, value string, flag uint8) {
	fqdn := dns.Fqdn(domain)
	m.caaRecords[fqdn] = append(m.caaRecords[fqdn], &dns.CAA{
		Hdr:   dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
		Tag:   tag,
		Value: value,
		Flag:  flag,
	})
}

func (m *caaFinalizeMockDNS) setRcode(domain string, rcode int) {
	m.rcode[dns.Fqdn(domain)] = rcode
}

func (m *caaFinalizeMockDNS) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	if rcode, ok := m.rcode[q.Name]; ok {
		msg.Rcode = rcode
		_ = w.WriteMsg(msg)
		return
	}

	if q.Qtype == dns.TypeCAA {
		msg.Answer = append(msg.Answer, dnsRRs(m.caaRecords[q.Name])...)
	}

	_ = w.WriteMsg(msg)
}

func dnsRRs(records []*dns.CAA) []dns.RR {
	rrs := make([]dns.RR, len(records))
	for i, r := range records {
		rrs[i] = r
	}
	return rrs
}

// startCAAFinalizeMockDNS starts the stub resolver and returns its address.
func startCAAFinalizeMockDNS(t *testing.T, mock *caaFinalizeMockDNS) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := conn.LocalAddr().String()

	srv := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(mock.handleDNS)}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }

	go func() {
		_ = srv.ActivateAndServe()
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for mock DNS server to start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })

	return addr
}

// finalizeCAAOrder finalizes a DNS-identifier order against the given
// caaIdentities/resolver, returning the HTTP response and the order as it
// stands in storage afterward.
func finalizeCAAOrder(t *testing.T, resolverAddr string, caaIdentities []string, wildcard bool) (*httptest.ResponseRecorder, *entities.ACMEOrder) {
	t.Helper()

	service, _, cleanup := setupTestServiceWithMockCA(t)
	defer cleanup()

	validator, err := acmeserver.NewCAAValidator(&acmeserver.CAAValidatorParams{
		Logger:        slog.Default(),
		Resolver:      resolverAddr,
		Timeout:       2 * time.Second,
		CAAIdentities: caaIdentities,
	})
	require.NoError(t, err)
	service.caaValidator = validator

	key := generateTestKey(t)
	account := createTestAccount(t, service, key)

	domain := "example.com"
	identifierValue := domain
	commonName := domain
	if wildcard {
		identifierValue = "*." + domain
		commonName = identifierValue
	}

	order := createTestOrderSimple(t, service, account.ID)
	order.Status = common.StatusReady
	order.Identifiers = []entities.ACMEIdentifier{
		{Type: common.AuthzTypeDNS, Value: identifierValue},
	}

	ctx := context.Background()
	orderDAO, err := service.storageFactory.OrderDAO(account.ID)
	require.NoError(t, err)
	require.NoError(t, orderDAO.Save(ctx, order))

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: commonName},
		DNSNames: []string{identifierValue},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	require.NoError(t, err)

	payload := OrderFinalizeRequest{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}
	url := fmt.Sprintf("%s/acme/orders/%d/finalize", service.baseRESTURI, order.ID)
	req := createJWSRequest(t, service, key, url, payload, true, account.ID)
	req = mux.SetURLVars(req, map[string]string{"id": fmt.Sprintf("%d", order.ID)})

	resp := httptest.NewRecorder()
	service.OrderFinalizeHandler(resp, req)

	got, err := orderDAO.Get(ctx, order.ID)
	require.NoError(t, err)

	return resp, got
}

// TestOrderFinalize_CAA_Forbidden verifies that a domain whose CAA record
// does not list this CA's issuer domain is refused: the response carries
// the RFC 8555 "caa" error type and the order is left invalid.
func TestOrderFinalize_CAA_Forbidden(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	mock.addCAARecord("example.com", "issue", "other-ca.example.net", 0)
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, false)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
	assert.Equal(t, common.StatusInvalid, order.Status)
}

// TestOrderFinalize_CAA_Permitted verifies that a domain whose CAA record
// names this CA's issuer domain is allowed to finalize.
func TestOrderFinalize_CAA_Permitted(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	mock.addCAARecord("example.com", "issue", "ca.example.com", 0)
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, false)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, common.StatusValid, order.Status)
}

// TestOrderFinalize_CAA_NoRecordPermitted verifies RFC 8659's default: a
// domain that publishes no CAA record at all permits any CA to issue.
func TestOrderFinalize_CAA_NoRecordPermitted(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, false)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, common.StatusValid, order.Status)
}

// TestOrderFinalize_CAA_WildcardIssuewild verifies that a wildcard order is
// checked against the issuewild property, per RFC 8659 Section 5.3, and
// succeeds when this CA's identity is listed there.
func TestOrderFinalize_CAA_WildcardIssuewild(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	mock.addCAARecord("example.com", "issuewild", "ca.example.com", 0)
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, true)

	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, common.StatusValid, order.Status)
}

// TestOrderFinalize_CAA_WildcardIssuewildForbidden verifies that a wildcard
// order is refused when issuewild names a different CA, even though this
// test does not configure an issue record at all (issuewild alone governs
// wildcard requests per RFC 8659 Section 5.3).
func TestOrderFinalize_CAA_WildcardIssuewildForbidden(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	mock.addCAARecord("example.com", "issuewild", "other-ca.example.net", 0)
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, true)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
	assert.Equal(t, common.StatusInvalid, order.Status)
}

// TestOrderFinalize_CAA_CriticalUnknownTagForbidden verifies RFC 8659
// Section 4: an unrecognized property tag with the critical flag set
// refuses issuance even though a matching issue record is also present.
func TestOrderFinalize_CAA_CriticalUnknownTagForbidden(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	mock.addCAARecord("example.com", "issue", "ca.example.com", 0)
	mock.addCAARecord("example.com", "unsupportedtag", "somevalue", 0x80)
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, false)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
	assert.Equal(t, common.StatusInvalid, order.Status)
}

// TestOrderFinalize_CAA_DNSFailureFailsClosed verifies RFC 8659 Section 5.1:
// a CA MUST NOT issue when it cannot determine the relevant CAA RRset, so a
// SERVFAIL from the resolver refuses issuance rather than "proceeding with
// caution".
func TestOrderFinalize_CAA_DNSFailureFailsClosed(t *testing.T) {
	mock := newCAAFinalizeMockDNS()
	mock.setRcode("example.com", dns.RcodeServerFailure)
	addr := startCAAFinalizeMockDNS(t, mock)

	resp, order := finalizeCAAOrder(t, addr, []string{"ca.example.com"}, false)

	assertErrorType(t, resp, common.ErrTypeCAAError, http.StatusUnauthorized)
	assert.Equal(t, common.StatusInvalid, order.Status)
}
