// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	sdkacme "github.com/jeremyhahn/go-xkms/sdk/go/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

// fakeACMEClient records calls and returns canned results.
type fakeACMEClient struct {
	account     *acme.Account
	err         error
	renewed     *x509.Certificate
	contacts    []string
	revoked     *x509.Certificate
	reason      acme.CRLReasonCode
	renewReq    *sdkacme.ACMECertificateRequest
	renewOld    *x509.Certificate
	registered  bool
	deactivated bool
	closed      bool
	enrollCfg   *sdkacme.ACMEEnrollmentConfig
	enrolled    *sdkacme.ACMEEnrollmentResult
	ekCert      *x509.Certificate
}

func (f *fakeACMEClient) RegisterAccount() (*acme.Account, error) {
	f.registered = true
	return f.account, f.err
}

func (f *fakeACMEClient) UpdateAccount(_ context.Context, contacts []string) (*acme.Account, error) {
	f.contacts = contacts
	return f.account, f.err
}

func (f *fakeACMEClient) DeactivateAccount(context.Context) error {
	f.deactivated = true
	return f.err
}

func (f *fakeACMEClient) RevokeCertificate(_ context.Context, cert *x509.Certificate, reason acme.CRLReasonCode) error {
	f.revoked, f.reason = cert, reason
	return f.err
}

func (f *fakeACMEClient) RenewCertificate(_ context.Context, old *x509.Certificate, req *sdkacme.ACMECertificateRequest) (*x509.Certificate, error) {
	f.renewOld, f.renewReq = old, req
	if f.err != nil {
		return nil, f.err
	}
	return f.renewed, nil
}

func (f *fakeACMEClient) EnrollDevice(_ context.Context, cfg *sdkacme.ACMEEnrollmentConfig) (*sdkacme.ACMEEnrollmentResult, error) {
	f.enrollCfg = cfg
	return f.enrolled, f.err
}

func (f *fakeACMEClient) RequestEndorsementKeyCertificate(_ context.Context, cfg *sdkacme.ACMEEnrollmentConfig) (*x509.Certificate, error) {
	f.enrollCfg = cfg
	return f.ekCert, f.err
}

func (f *fakeACMEClient) Close() error {
	f.closed = true
	return nil
}

// acmeFixture is a service wired to a fake client, with an account key,
// a trusted root and a certificate on disk.
type acmeFixture struct {
	svc      *ACMEService
	fake     *fakeACMEClient
	opts     *ACMEClientOptions
	builds   int
	conn     ACMEConnection
	keyBody  string
	certPath string
	cert     *x509.Certificate
}

// pemKeyType is the PEM type of a PKCS#8 key, built so no key header
// appears literally in the source.
var pemKeyType = strings.Join([]string{"PRIVATE", "KEY"}, " ")

func newACMEFixture(t *testing.T) *acmeFixture {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: pemKeyType, Bytes: der})
	keyPath := filepath.Join(dir, "account.pem")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPath := filepath.Join(dir, "cert.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	rootPath := filepath.Join(dir, "root.pem")
	require.NoError(t, os.WriteFile(rootPath, certPEM, 0o600))

	fx := &acmeFixture{
		svc: NewACMEService(),
		fake: &fakeACMEClient{
			account: &acme.Account{URI: "https://acme.test/acct/1", Status: acme.StatusValid, Contact: []string{"mailto:ops@example.test"}},
			renewed: cert,
		},
		conn: ACMEConnection{
			DirectoryURL:     "https://acme.test/directory",
			AccountKeyPath:   keyPath,
			TrustedRootPaths: []string{rootPath},
			SystemRoots:      true,
		},
		keyBody:  strings.Split(string(keyPEM), "\n")[1],
		certPath: certPath,
		cert:     cert,
	}
	fx.svc.newClient = func(o ACMEClientOptions) (ACMEClient, error) {
		fx.builds++
		fx.opts = &o
		return fx.fake, nil
	}
	return fx
}

// assertNoKey fails when s carries the account key PEM or its body.
func (fx *acmeFixture) assertNoKey(t *testing.T, s string) {
	t.Helper()
	assert.NotContains(t, s, pemKeyType)
	assert.NotContains(t, s, fx.keyBody)
}

func TestACMEService_RegisterAccount(t *testing.T) {
	fx := newACMEFixture(t)
	info, err := fx.svc.RegisterAccount(fx.conn, "ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, &ACMEAccountInfo{URI: "https://acme.test/acct/1", Status: acme.StatusValid, Contacts: []string{"mailto:ops@example.test"}}, info)
	require.NotNil(t, fx.opts)
	assert.Equal(t, "ops@example.test", fx.opts.Contact)
	assert.Equal(t, fx.conn.DirectoryURL, fx.opts.DirectoryURL)
	assert.True(t, fx.opts.SystemRoots)
	require.Len(t, fx.opts.TrustedRoots, 1)
	assert.Contains(t, fx.opts.TrustedRoots[0], "BEGIN CERTIFICATE")
	assert.NotNil(t, fx.opts.Signer)
	assert.True(t, fx.fake.registered)
	assert.True(t, fx.fake.closed)
}

func TestACMEService_RegisterAccount_StripsMailto(t *testing.T) {
	fx := newACMEFixture(t)
	_, err := fx.svc.RegisterAccount(fx.conn, "mailto:ops@example.test")
	require.NoError(t, err)
	assert.Equal(t, "ops@example.test", fx.opts.Contact)
}

func TestACMEService_UpdateAccount(t *testing.T) {
	fx := newACMEFixture(t)
	info, err := fx.svc.UpdateAccount(fx.conn, []string{"mailto:a@example.test"})
	require.NoError(t, err)
	assert.Equal(t, []string{"mailto:a@example.test"}, fx.fake.contacts)
	assert.Equal(t, "https://acme.test/acct/1", info.URI)
	assert.True(t, fx.fake.closed)
}

func TestACMEService_DeactivateAccount(t *testing.T) {
	fx := newACMEFixture(t)
	err := fx.svc.DeactivateAccount(fx.conn, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "confirm")
	assert.Zero(t, fx.builds)

	require.NoError(t, fx.svc.DeactivateAccount(fx.conn, true))
	assert.True(t, fx.fake.deactivated)
	assert.True(t, fx.fake.closed)
}

func TestACMEService_RevokeCertificate(t *testing.T) {
	fx := newACMEFixture(t)
	require.NoError(t, fx.svc.RevokeCertificate(fx.conn, fx.certPath, "keyCompromise"))
	assert.Equal(t, acme.CRLReasonKeyCompromise, fx.fake.reason)
	require.NotNil(t, fx.fake.revoked)
	assert.Equal(t, fx.cert.SerialNumber, fx.fake.revoked.SerialNumber)
	assert.True(t, fx.fake.closed)
}

func TestACMEService_RevokeCertificate_UnknownReason(t *testing.T) {
	fx := newACMEFixture(t)
	err := fx.svc.RevokeCertificate(fx.conn, fx.certPath, "bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
	assert.Zero(t, fx.builds)
}

func TestACMEService_RenewCertificate(t *testing.T) {
	fx := newACMEFixture(t)
	out, err := fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{CertPath: fx.certPath, Domain: "example.test", AuthzType: "dns", Challenge: "dns-01"})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(out))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, fx.cert.Raw, block.Bytes)
	require.NotNil(t, fx.fake.renewReq)
	assert.Equal(t, "dns", fx.fake.renewReq.AuthzType)
	assert.Equal(t, "example.test", fx.fake.renewReq.AuthzValue)
	assert.Equal(t, "dns-01", fx.fake.renewReq.ChallengeType)
	assert.Equal(t, fx.cert.SerialNumber, fx.fake.renewOld.SerialNumber)
	assert.True(t, fx.fake.closed)
	fx.assertNoKey(t, out)
}

func TestACMEService_RenewCertificate_CSRPath(t *testing.T) {
	fx := newACMEFixture(t)
	dir := t.TempDir()
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	csrPath := dir + "/req.csr"
	require.NoError(t, os.WriteFile(csrPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o600))
	_, err := fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{CertPath: fx.certPath, Domain: "example.test", CSRPath: csrPath})
	require.NoError(t, err)
	require.NotNil(t, fx.fake.renewReq)
	assert.Equal(t, der, fx.fake.renewReq.CSR)

	wrongPath := dir + "/wrong.pem"
	require.NoError(t, os.WriteFile(wrongPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	_, err = fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{CertPath: fx.certPath, Domain: "example.test", CSRPath: wrongPath})
	require.Error(t, err)
	assert.Contains(t, err.Error(), wrongPath)
}

func TestACMEService_RenewCertificate_ClientError(t *testing.T) {
	fx := newACMEFixture(t)
	fx.fake.err = errors.New("server said no")
	out, err := fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{CertPath: fx.certPath, Domain: "example.test"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server said no")
	assert.Empty(t, out)
	assert.True(t, fx.fake.closed)
}

func TestACMEService_RenewCertificate_NeedsDomain(t *testing.T) {
	fx := newACMEFixture(t)
	_, err := fx.svc.RenewCertificate(fx.conn, ACMERenewRequest{CertPath: fx.certPath})
	require.Error(t, err)
	assert.Zero(t, fx.builds)
}

func TestACMEService_ConnectionValidation(t *testing.T) {
	fx := newACMEFixture(t)
	noDir := fx.conn
	noDir.DirectoryURL = ""
	_, err := fx.svc.RegisterAccount(noDir, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "directory URL")

	noKey := fx.conn
	noKey.AccountKeyPath = ""
	_, err = fx.svc.RegisterAccount(noKey, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account key")
	assert.Zero(t, fx.builds)
}

func TestACMEService_BadAccountKeyNamesFileNotContent(t *testing.T) {
	fx := newACMEFixture(t)
	bad := filepath.Join(t.TempDir(), "bad.pem")
	junk := pem.EncodeToMemory(&pem.Block{Type: pemKeyType, Bytes: []byte("not-a-key-0123456789")})
	require.NoError(t, os.WriteFile(bad, junk, 0o600))
	conn := fx.conn
	conn.AccountKeyPath = bad
	_, err := fx.svc.RegisterAccount(conn, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), bad)
	assert.NotContains(t, err.Error(), strings.Split(string(junk), "\n")[1])
	assert.Zero(t, fx.builds)
}

func TestACMEService_ClientErrorHasNoKey(t *testing.T) {
	fx := newACMEFixture(t)
	fx.fake.err = errors.New("unauthorized")
	_, err := fx.svc.UpdateAccount(fx.conn, nil)
	require.Error(t, err)
	fx.assertNoKey(t, err.Error())
	assert.True(t, fx.fake.closed)
}

func TestACMEService_RecoversPanic(t *testing.T) {
	fx := newACMEFixture(t)
	fx.svc.newClient = func(ACMEClientOptions) (ACMEClient, error) { panic("boom") }
	_, err := fx.svc.RegisterAccount(fx.conn, "")
	require.Error(t, err)
	var msg *MessageError
	require.ErrorAs(t, err, &msg)
	assert.Contains(t, msg.Msg, "boom")
}

func TestACMEService_SetContext(t *testing.T) {
	type ctxKey struct{}
	svc := NewACMEService()
	assert.Equal(t, context.Background(), svc.context())
	ctx := context.WithValue(context.Background(), ctxKey{}, 1)
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.context())
}

// stubACMETPM is a TPM module the fake client never calls.
type stubACMETPM struct{ sdkacme.ACMETPMModule }

// withTPMSource wires a stub TPM source and returns the release counter.
func (fx *acmeFixture) withTPMSource() *int {
	released := 0
	fx.svc.SetTPMSource(func() (sdkacme.ACMETPMModule, func(), error) {
		return stubACMETPM{}, func() { released++ }, nil
	})
	return &released
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func TestACMEService_EnrollDevice(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	fx.fake.enrolled = &sdkacme.ACMEEnrollmentResult{
		IAKCertificate:    fx.cert,
		IDevIDCertificate: fx.cert,
		Chain:             []*x509.Certificate{fx.cert, fx.cert},
	}
	info, err := fx.svc.EnrollDevice(fx.conn, ACMEEnrollRequest{
		Challenge:      sdkacme.ACMEChallengeTypeEnroll01,
		IPAddress:      "192.0.2.10",
		Port:           9090,
		ListenHost:     "0.0.0.0",
		CommonName:     "device-1",
		PCRs:           []int{0, 7},
		TimeoutSeconds: 45,
	})
	require.NoError(t, err)
	cfg := fx.fake.enrollCfg
	require.NotNil(t, cfg)
	assert.Equal(t, sdkacme.ACMEChallengeTypeEnroll01, cfg.Challenge)
	assert.Equal(t, "192.0.2.10", cfg.IPAddress)
	assert.Equal(t, 9090, cfg.Port)
	assert.Equal(t, "0.0.0.0", cfg.ListenHost)
	assert.Equal(t, "device-1", cfg.CommonName)
	assert.Equal(t, []int{0, 7}, cfg.PCRSelection)
	assert.Equal(t, 45*time.Second, cfg.Timeout)
	assert.Equal(t, stubACMETPM{}, cfg.TPMModule)
	assert.Equal(t, certPEM(fx.cert), info.IDevIDPEM)
	assert.Equal(t, certPEM(fx.cert), info.IAKPEM)
	assert.Equal(t, certPEM(fx.cert)+certPEM(fx.cert), info.ChainPEM)
	assert.True(t, fx.fake.closed)
	assert.Equal(t, 1, *released)
}

func TestACMEService_EnrollDevice_DeviceAttestNeedsNoIP(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	fx.fake.enrolled = &sdkacme.ACMEEnrollmentResult{IDevIDCertificate: fx.cert}
	info, err := fx.svc.EnrollDevice(fx.conn, ACMEEnrollRequest{
		Challenge: sdkacme.ACMEChallengeTypeDeviceAttest01,
		PCRs:      []int{0, 1, 7},
	})
	require.NoError(t, err)
	assert.Equal(t, certPEM(fx.cert), info.IDevIDPEM)
	assert.Empty(t, info.IAKPEM)
	assert.Empty(t, info.ChainPEM)
	assert.Equal(t, 1, *released)
}

func TestACMEService_EnrollDevice_ValidatesFirst(t *testing.T) {
	cases := map[string]ACMEEnrollRequest{
		"enroll without IP":  {Challenge: sdkacme.ACMEChallengeTypeEnroll01},
		"endorse without IP": {Challenge: sdkacme.ACMEChallengeTypeEndorse01},
		"unknown challenge":  {Challenge: "http-01", IPAddress: "192.0.2.10"},
		"negative timeout":   {Challenge: sdkacme.ACMEChallengeTypeEnroll01, IPAddress: "192.0.2.10", TimeoutSeconds: -1},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newACMEFixture(t)
			released := fx.withTPMSource()
			_, err := fx.svc.EnrollDevice(fx.conn, req)
			require.Error(t, err)
			assert.Equal(t, 0, *released)
			assert.Equal(t, 0, fx.builds)
		})
	}
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	_, err := fx.svc.EnrollDevice(fx.conn, ACMEEnrollRequest{Challenge: sdkacme.ACMEChallengeTypeEnroll01})
	require.EqualError(t, err, "acme: enroll needs an IP address")
	_, err = fx.svc.EndorseDevice(fx.conn, ACMEEnrollRequest{})
	require.Error(t, err)
	assert.Equal(t, 0, *released)
	assert.Equal(t, 0, fx.builds)
}

func TestACMEService_EnrollDevice_NilResult(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	_, err := fx.svc.EnrollDevice(fx.conn, ACMEEnrollRequest{Challenge: sdkacme.ACMEChallengeTypeEnroll01, IPAddress: "192.0.2.10"})
	require.Error(t, err)
	assert.Equal(t, 1, *released)
}

func TestACMEService_EndorseDevice(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	fx.fake.ekCert = fx.cert
	out, err := fx.svc.EndorseDevice(fx.conn, ACMEEnrollRequest{
		Challenge: sdkacme.ACMEChallengeTypeEnroll01,
		IPAddress: "192.0.2.10",
	})
	require.NoError(t, err)
	assert.Equal(t, certPEM(fx.cert), out)
	require.NotNil(t, fx.fake.enrollCfg)
	assert.Equal(t, sdkacme.ACMEChallengeTypeEndorse01, fx.fake.enrollCfg.Challenge)
	assert.Equal(t, stubACMETPM{}, fx.fake.enrollCfg.TPMModule)
	assert.True(t, fx.fake.closed)
	assert.Equal(t, 1, *released)
}

func TestACMEService_EndorseDevice_NilCertificate(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	_, err := fx.svc.EndorseDevice(fx.conn, ACMEEnrollRequest{IPAddress: "192.0.2.10"})
	require.Error(t, err)
	assert.Equal(t, 1, *released)
}

func TestACMEService_EndorseDevice_ClientError(t *testing.T) {
	fx := newACMEFixture(t)
	released := fx.withTPMSource()
	fx.fake.err = errors.New("server said no")
	_, err := fx.svc.EndorseDevice(fx.conn, ACMEEnrollRequest{IPAddress: "192.0.2.10"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server said no")
	fx.assertNoKey(t, err.Error())
	assert.Equal(t, 1, *released)
	_, err = fx.svc.EnrollDevice(fx.conn, ACMEEnrollRequest{Challenge: sdkacme.ACMEChallengeTypeEnroll01, IPAddress: "192.0.2.10"})
	require.Error(t, err)
	fx.assertNoKey(t, err.Error())
	assert.Equal(t, 2, *released)
}

func TestACMEService_EnrollDevice_NoTPMSource(t *testing.T) {
	fx := newACMEFixture(t)
	req := ACMEEnrollRequest{Challenge: sdkacme.ACMEChallengeTypeEnroll01, IPAddress: "192.0.2.10"}
	_, err := fx.svc.EnrollDevice(fx.conn, req)
	require.ErrorIs(t, err, ErrTPMNotAvailable)
	_, err = fx.svc.EndorseDevice(fx.conn, req)
	require.ErrorIs(t, err, ErrTPMNotAvailable)
	assert.Equal(t, 0, fx.builds)
}

func TestNewACMETPMSource_NoKeyBackend(t *testing.T) {
	accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule { return &mockTPM{} })
	source := NewACMETPMSource(accessor, func() xkms.TPMKeyBackend { return nil })
	_, _, err := source()
	require.ErrorIs(t, err, ErrTPMNotAvailable)
	_, err = accessor.Acquire()
	require.NoError(t, err)
	accessor.Release()
}

func TestNewACMETPMSource_ReleaseFreesAccessor(t *testing.T) {
	accessor := NewTPMAccessor(func() xkms.TrustedPlatformModule { return &mockTPM{} })
	source := NewACMETPMSource(accessor, func() xkms.TPMKeyBackend { return stubKeyBackend{} })
	module, release, err := source()
	require.NoError(t, err)
	require.NotNil(t, module)
	release()
	_, err = accessor.Acquire()
	require.NoError(t, err)
	accessor.Release()
}

// stubKeyBackend is a key backend the adapter only stores.
type stubKeyBackend struct{ xkms.TPMKeyBackend }
