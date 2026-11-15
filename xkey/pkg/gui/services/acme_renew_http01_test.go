package services

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/stretchr/testify/require"
)

// http01CA stands in for the ACME CA behind a pending http-01
// authorization: like pkg/acme/client.RequestCertificate it hands the token
// and key authorization to req.ChallengeSetup, then, as the CA, fetches the
// token from the address the device serves it on, and issues only when the
// served key authorization matches.
type http01CA struct {
	*fakeACMEClient
	addr    string
	fetched string
	cleaned bool
}

func (c *http01CA) RenewCertificate(ctx context.Context, old *x509.Certificate, req *sdkacme.ACMECertificateRequest) (*x509.Certificate, error) {
	const token = "pending-http01-token"
	keyAuth := token + ".account-thumbprint"
	if req.ChallengeSetup == nil {
		return nil, errors.New("no challenge setup: the CA cannot fetch the http-01 token")
	}
	if err := req.ChallengeSetup(req.ChallengeType, token, keyAuth); err != nil {
		return nil, err
	}
	body, err := fetchHTTP01Token(c.addr, token)
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

func fetchHTTP01Token(addr, token string) (string, error) {
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

// freeLoopbackAddr returns a loopback address with a port nothing listens on.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func TestACMEService_RenewCertificate_AnswersPendingHTTP01(t *testing.T) {
	fx := newACMEFixture(t)
	ca := &http01CA{fakeACMEClient: fx.fake, addr: freeLoopbackAddr(t)}
	fx.svc.newClient = func(ACMEClientOptions) (ACMEClient, error) { return ca, nil }
	csrPath, _ := writeACMETestCSR(t)
	out, err := fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{
		CertPath: fx.certPath, Domain: "example.test", AuthzType: "dns",
		Challenge: "http-01", CSRPath: csrPath, HTTPAddr: ca.addr,
	})
	require.NoError(t, err)
	require.NotEmpty(t, out)
	require.Equal(t, "pending-http01-token.account-thumbprint", ca.fetched)
	require.True(t, ca.cleaned, "challenge cleanup did not run")
	// Cleanup stopped the responder: the port is free again.
	l, err := net.Listen("tcp", ca.addr)
	require.NoError(t, err)
	require.NoError(t, l.Close())
}

func TestACMEService_RenewCertificate_DNS01NeedsAProvider(t *testing.T) {
	fx := newACMEFixture(t)
	csrPath, _ := writeACMETestCSR(t)
	_, err := fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{
		CertPath: fx.certPath, Domain: "example.test", AuthzType: "dns",
		Challenge: "dns-01", CSRPath: csrPath,
	})
	require.ErrorContains(t, err, "DNS provider")
	require.Nil(t, fx.fake.renewReq, "renewal reached the CA without a dns-01 solver")
}
