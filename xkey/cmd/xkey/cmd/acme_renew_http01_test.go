package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// cliHTTP01CA stands in for the ACME CA behind a pending http-01
// authorization: like pkg/acme/client.RequestCertificate it hands the token
// and key authorization to req.ChallengeSetup, then, as the CA, fetches the
// token from the address xkey serves it on, and issues only when the served
// key authorization matches.
type cliHTTP01CA struct {
	*fakeACMEClient
	addr    string
	fetched string
	cleaned bool
}

func (c *cliHTTP01CA) RenewCertificate(ctx context.Context, old *x509.Certificate, req *sdkacme.ACMECertificateRequest) (*x509.Certificate, error) {
	const token = "pending-http01-token"
	keyAuth := token + ".account-thumbprint"
	if req.ChallengeSetup == nil {
		return nil, errors.New("no challenge setup: the CA cannot fetch the http-01 token")
	}
	if err := req.ChallengeSetup(req.ChallengeType, token, keyAuth); err != nil {
		return nil, err
	}
	body, err := cliFetchHTTP01Token(c.addr, token)
	if req.ChallengeCleanup != nil {
		req.ChallengeCleanup(req.ChallengeType)
		c.cleaned = true
	}
	if err != nil {
		return nil, err
	}
	if body != keyAuth {
		return nil, fmt.Errorf("served key authorization %q, want %q", body, keyAuth)
	}
	c.fetched = body
	return c.fakeACMEClient.RenewCertificate(ctx, old, req)
}

func cliFetchHTTP01Token(addr, token string) (string, error) {
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get("http://" + addr + "/.well-known/acme-challenge/" + token)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token fetch: status %d", resp.StatusCode)
	}
	return string(b), nil
}

func TestACMERenewAnswersPendingHTTP01(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, _ := writeTestCert(t)
	_, renewed := writeTestCert(t)
	env.fake.renewed = renewed
	csrFile, _ := writeACMETestCSR(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	ca := &cliHTTP01CA{fakeACMEClient: env.fake, addr: addr}
	prev := newACMEClientFunc
	newACMEClientFunc = func(services.ACMEClientOptions) (services.ACMEClient, error) { return ca, nil }
	t.Cleanup(func() { newACMEClientFunc = prev })

	args := append([]string{"renew", "--cert", certFile, "--domain", "device.test",
		"--challenge", "http-01", "--csr", csrFile, "--http-addr", addr}, env.common()...)
	out, err := env.run(t, args...)
	if err != nil {
		t.Fatalf("renew: %v (%s)", err, out)
	}
	if ca.fetched != "pending-http01-token.account-thumbprint" {
		t.Fatalf("CA fetched %q", ca.fetched)
	}
	if !ca.cleaned {
		t.Fatal("challenge cleanup did not run")
	}
	if block, _ := pem.Decode([]byte(out)); block == nil || string(block.Bytes) != string(renewed.Raw) {
		t.Fatalf("output is not the renewed certificate: %q", out)
	}
	// Cleanup stopped the responder: the port is free again.
	l, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("responder still bound after cleanup: %v", err)
	}
	_ = l.Close()
}

func TestACMERenewDNS01NeedsAProvider(t *testing.T) {
	env := newACMETestEnv(t)
	certFile, _ := writeTestCert(t)
	csrFile, _ := writeACMETestCSR(t)
	args := append([]string{"renew", "--cert", certFile, "--domain", "device.test",
		"--challenge", "dns-01", "--csr", csrFile}, env.common()...)
	out, err := env.run(t, args...)
	if err == nil || !strings.Contains(err.Error(), "DNS provider") {
		t.Fatalf("renew dns-01: err = %v (%s), want an error naming the missing DNS provider", err, out)
	}
	if env.fake.renewReq != nil {
		t.Fatal("renewal reached the CA without a dns-01 solver")
	}
}
