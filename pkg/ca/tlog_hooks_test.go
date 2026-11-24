package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca/tlog"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// tlogRecorder is a tlog.Appender recording every (log, entry) pair.
type tlogRecorder struct {
	logs    []string
	entries []map[string]any
}

func (r *tlogRecorder) Append(_ context.Context, log string, entry []byte) error {
	var m map[string]any
	if err := json.Unmarshal(entry, &m); err != nil {
		return err
	}
	r.logs = append(r.logs, log)
	r.entries = append(r.entries, m)
	return nil
}

func newTlogHookCA(t *testing.T, rec tlog.Appender) *CA {
	t.Helper()
	sw, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := xkms.New(&xkms.BackendConfig{Backend: sw, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	cs, err := certstore.New(&certstore.Config{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "Tlog Root CA"
	config.Identity[0].Subject.Organization = "Test Organization"
	config.Identity[0].Keys[0].KeyType = "CA"
	iface, err := NewFromMultiIdentityConfig(&MultiIdentityParams{
		Config:          config,
		KeyStore:        backend,
		BackendForStore: singleBackendFactory(backend),
		RevocationStore: storage.NewMemory(),
		CertStore:       cs,
		TransparencyLog: rec,
	})
	require.NoError(t, err)
	require.NoError(t, iface.Init(context.Background()))
	return iface.(*CA)
}

func tlogCSR(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
	}, k)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestTlogHook_IssuanceAppendsCertIssued(t *testing.T) {
	rec := &tlogRecorder{}
	c := newTlogHookCA(t, rec)
	cert, err := c.SignCSR(context.Background(), tlogCSR(t, "leaf.example.com"),
		&SignOptions{Profile: "server", TenantID: "acme"})
	require.NoError(t, err)

	require.Equal(t, []string{tlog.LogIssuance}, rec.logs)
	sum := sha256.Sum256(cert.Raw)
	require.Equal(t, map[string]any{
		"kind":    tlog.KindCertIssued,
		"sha256":  hex.EncodeToString(sum[:]),
		"serial":  cert.SerialNumber.Text(16),
		"profile": "server",
		"tenant":  "acme",
	}, rec.entries[0])
}

func TestTlogHook_PrecertificateAppendsNothing(t *testing.T) {
	rec := &tlogRecorder{}
	c := newTlogHookCA(t, rec)
	_, err := c.SignCSR(context.Background(), tlogCSR(t, "pre.example.com"),
		&SignOptions{Precertificate: true, TenantID: "acme"})
	require.NoError(t, err)
	require.Empty(t, rec.logs)
}

type failingTlog struct{}

func (failingTlog) Append(context.Context, string, []byte) error { return errTlogDown }

var errTlogDown = &tlog.AppendError{Log: "x", Err: context.DeadlineExceeded}

func TestTlogHook_IssuanceAppendFailureIsAppendError(t *testing.T) {
	c := newTlogHookCA(t, failingTlog{})
	_, err := c.SignCSR(context.Background(), tlogCSR(t, "fail.example.com"), &SignOptions{TenantID: "acme"})
	var ae *tlog.AppendError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, tlog.LogIssuance, ae.Log)
}

func TestTlogHook_RevokeAppendsRevokedOnce(t *testing.T) {
	rec := &tlogRecorder{}
	c := newTlogHookCA(t, rec)
	cert, err := c.SignCSR(context.Background(), tlogCSR(t, "rev.example.com"),
		&SignOptions{TenantID: "acme"})
	require.NoError(t, err)
	rec.logs, rec.entries = nil, nil

	require.NoError(t, c.Revoke(context.Background(), cert.SerialNumber, 1))
	require.ErrorIs(t, c.Revoke(context.Background(), cert.SerialNumber, 1), ErrAlreadyRevoked)

	require.Equal(t, []string{tlog.LogRevocation}, rec.logs)
	require.Equal(t, map[string]any{
		"kind":   tlog.KindRevoked,
		"serial": cert.SerialNumber.Text(16),
		"reason": RevocationReasonName(ReasonKeyCompromise),
	}, rec.entries[0])
}
