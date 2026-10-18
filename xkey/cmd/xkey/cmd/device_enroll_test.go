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

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// --- in-process certificate authority ---

// testCA is a minimal in-process certificate authority used to exercise the
// enrollment path end to end without a live xkmsd server. It signs the CSR
// the command generates, so the issued certificate really matches the agent
// key and can be loaded as a TLS client certificate.
type testCA struct {
	key      *ecdsa.PrivateKey
	cert     *x509.Certificate
	certPEM  []byte
	signErr  error
	caErr    error
	caPEM    []byte
	closed   bool
	lastCSR  []byte
	profile  string
	validity int
}

// newTestCA creates a self-signed authority.
func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkey test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return &testCA{key: key, cert: cert, certPEM: certPEM, caPEM: certPEM}
}

// SignCSR issues a leaf certificate for the public key in the request.
func (c *testCA) SignCSR(csrPEM []byte) ([]byte, error) {
	c.lastCSR = csrPEM
	if c.signErr != nil {
		return nil, c.signErr
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("test ca: csr is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// GetCACertificate returns the authority's trust anchor.
func (c *testCA) GetCACertificate() ([]byte, error) {
	if c.caErr != nil {
		return nil, c.caErr
	}
	return c.caPEM, nil
}

// Close records that the caller released the authority client.
func (c *testCA) Close() error {
	c.closed = true
	return nil
}

// issueServerCert issues a TLS server certificate valid for 127.0.0.1.
func (c *testCA) issueServerCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	return certificate
}

// issueClientCert issues a TLS client certificate and returns it with the
// matching key, mirroring what an enrolled agent holds.
func (c *testCA) issueClientCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "agent"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	require.NoError(t, err)
	return certificate
}

// --- helpers ---

// newDeviceEnrollCmd builds an enroll command carrying the flags the real
// command declares, bound to an output buffer.
func newDeviceEnrollCmd(t *testing.T, out *bytes.Buffer) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("code", "", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("cert-profile", agent.CertProfileDefault, "")
	cmd.Flags().Int("validity-days", 0, "")
	cmd.SetOut(out)
	return cmd
}

// installDeviceEnrollDoubles points the enroll command at an in-process
// certificate authority and a recording master probe.
func installDeviceEnrollDoubles(t *testing.T, ca *testCA, caErr error, probeErr error) *string {
	t.Helper()

	originalCA := deviceEnrollCAFactory
	originalProbe := deviceEnrollMasterProbe

	probedAddress := new(string)

	deviceEnrollCAFactory = func(profile string, validityDays int) (deviceEnrollCA, error) {
		if caErr != nil {
			return nil, caErr
		}
		ca.profile = profile
		ca.validity = validityDays
		return ca, nil
	}
	deviceEnrollMasterProbe = func(address string, _ tls.Certificate, _ *x509.CertPool) error {
		*probedAddress = address
		return probeErr
	}

	t.Cleanup(func() {
		deviceEnrollCAFactory = originalCA
		deviceEnrollMasterProbe = originalProbe
	})

	return probedAddress
}

// --- runDeviceEnroll ---

// TestRunDeviceEnroll_IssuesAndPersistsCertificate verifies enrollment really
// submits the CSR to the certificate authority, persists the issued
// certificate together with the trust anchor, and contacts the master. Before
// this was implemented the command only wrote a key and a CSR and claimed an
// "enrollment request prepared".
func TestRunDeviceEnroll_IssuesAndPersistsCertificate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ca := newTestCA(t)
	probed := installDeviceEnrollDoubles(t, ca, nil, nil)

	var out bytes.Buffer
	cmd := newDeviceEnrollCmd(t, &out)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "name", "workstation-1"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "validity-days", "90"))

	require.NoError(t, runDeviceEnroll(cmd, nil))

	// The authority received the generated CSR under the requested profile.
	require.NotEmpty(t, ca.lastCSR)
	assert.Equal(t, agent.CertProfileDefault, ca.profile)
	assert.Equal(t, 90, ca.validity)
	assert.True(t, ca.closed, "the authority client must be released")

	csrBlock, _ := pem.Decode(ca.lastCSR)
	require.NotNil(t, csrBlock)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "workstation-1", csr.Subject.CommonName)

	// The master was contacted with the freshly issued credentials.
	assert.Equal(t, "master.example.com:9443", *probed)

	certDir := mustAgentCertDir(t)
	keyPath := filepath.Join(certDir, deviceEnrollKeyFile)
	certPath := filepath.Join(certDir, deviceEnrollCertFile)
	caPath := filepath.Join(certDir, deviceEnrollCAFile)
	csrPath := filepath.Join(certDir, deviceEnrollCSRFile)

	for _, path := range []string{keyPath, certPath, caPath, csrPath} {
		_, statErr := os.Stat(path)
		require.NoError(t, statErr, "expected %s to be written", path)
	}

	keyInfo, err := os.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm(), "the agent key must not be world readable")

	// The persisted certificate is usable as a TLS client certificate and
	// chains to the persisted trust anchor.
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))

	leafBlock, _ := pem.Decode(certPEM)
	require.NotNil(t, leafBlock)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	require.NoError(t, err)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.NoError(t, err)

	assert.Contains(t, out.String(), "Enrollment complete")
	assert.Contains(t, out.String(), "accepted the certificate")
	assert.NotContains(t, out.String(), "pending enrollment completion")
}

// TestRunDeviceEnroll_DefaultsNameToHostname verifies the agent name falls
// back to the host name when --name is omitted.
func TestRunDeviceEnroll_DefaultsNameToHostname(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ca := newTestCA(t)
	installDeviceEnrollDoubles(t, ca, nil, nil)

	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))

	require.NoError(t, runDeviceEnroll(cmd, nil))

	csrBlock, _ := pem.Decode(ca.lastCSR)
	require.NotNil(t, csrBlock)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	require.NoError(t, err)

	hostname, err := os.Hostname()
	require.NoError(t, err)
	assert.Equal(t, hostname, csr.Subject.CommonName)
}

// TestRunDeviceEnroll_MissingServer verifies the command refuses to run
// without a master address.
func TestRunDeviceEnroll_MissingServer(t *testing.T) {
	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceEnrollServerRequired)
}

// TestRunDeviceEnroll_InvalidServer verifies a master address without a port
// is rejected before any key material is generated.
func TestRunDeviceEnroll_InvalidServer(t *testing.T) {
	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceEnrollServerInvalid)
}

// TestRunDeviceEnroll_CodeFailsClosed verifies a one-time enrollment code is
// refused with an explanation instead of being silently ignored.
func TestRunDeviceEnroll_CodeFailsClosed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	installDeviceEnrollDoubles(t, newTestCA(t), nil, nil)

	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "code", "ABCD1234"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceEnrollCodeUnsupported)

	_, statErr := os.Stat(filepath.Join(mustAgentCertDir(t), deviceEnrollKeyFile))
	assert.True(t, os.IsNotExist(statErr), "no key material should be written on a refused enrollment")
}

// TestRunDeviceEnroll_NoCertificateAuthority verifies an unreachable
// authority fails closed rather than writing a half-finished enrollment.
func TestRunDeviceEnroll_NoCertificateAuthority(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	installDeviceEnrollDoubles(t, nil, ErrAgentCAUnavailable, nil)

	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAgentCAUnavailable)

	_, statErr := os.Stat(filepath.Join(mustAgentCertDir(t), deviceEnrollCertFile))
	assert.True(t, os.IsNotExist(statErr))
}

// TestRunDeviceEnroll_SignFailure verifies a rejected CSR is surfaced.
func TestRunDeviceEnroll_SignFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ca := newTestCA(t)
	ca.signErr = agent.ErrCASignFailed
	installDeviceEnrollDoubles(t, ca, nil, nil)

	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, agent.ErrCASignFailed)
}

// TestRunDeviceEnroll_CACertificateFailure verifies a missing trust anchor is
// surfaced.
func TestRunDeviceEnroll_CACertificateFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ca := newTestCA(t)
	ca.caErr = agent.ErrCACertFailed
	installDeviceEnrollDoubles(t, ca, nil, nil)

	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, agent.ErrCACertFailed)
}

// TestRunDeviceEnroll_UnusableTrustAnchor verifies a CA response that is not
// a certificate is rejected.
func TestRunDeviceEnroll_UnusableTrustAnchor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	ca := newTestCA(t)
	ca.caPEM = []byte("not a certificate")
	installDeviceEnrollDoubles(t, ca, nil, nil)

	cmd := newDeviceEnrollCmd(t, &bytes.Buffer{})
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceEnrollTrustAnchorInvalid)
}

// TestRunDeviceEnroll_MasterRejects verifies a master that will not accept
// the issued certificate makes the command fail, with the credentials left on
// disk for inspection.
func TestRunDeviceEnroll_MasterRejects(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	installDeviceEnrollDoubles(t, newTestCA(t), nil, errors.New("remote error: tls: bad certificate"))

	var out bytes.Buffer
	cmd := newDeviceEnrollCmd(t, &out)
	require.NoError(t, setFlagForTest(t, cmd.Flags(), "server", "master.example.com:9443"))

	err := runDeviceEnroll(cmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDeviceEnrollMasterUnreachable)
	assert.Contains(t, err.Error(), "bad certificate")
	assert.NotContains(t, out.String(), "Enrollment complete")

	// The issued material is still available to the operator.
	_, statErr := os.Stat(filepath.Join(mustAgentCertDir(t), deviceEnrollCertFile))
	assert.NoError(t, statErr)
}

// --- probeMasterWithClientCert ---

// startMTLSListener starts an in-process TLS 1.3 listener that requires and
// verifies client certificates issued by ca. When speak is true the listener
// answers with a byte once the handshake completes, mirroring a gRPC server
// sending its HTTP/2 settings frame.
func startMTLSListener(t *testing.T, ca *testCA, clientAuth tls.ClientAuthType, speak bool) string {
	t.Helper()

	clientCAs := x509.NewCertPool()
	require.True(t, clientCAs.AppendCertsFromPEM(ca.certPEM))

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{ca.issueServerCert(t)},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if speak {
					_, _ = conn.Write([]byte{0x00})
				}
				// Read once so the TLS 1.3 client certificate is verified,
				// exactly as a gRPC server would when it reads the preface.
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()

	return listener.Addr().String()
}

// TestProbeMasterWithClientCert_AcceptedWhenMasterSpeaks verifies the probe
// reports success as soon as an accepting master sends its first bytes.
func TestProbeMasterWithClientCert_AcceptedWhenMasterSpeaks(t *testing.T) {
	ca := newTestCA(t)
	address := startMTLSListener(t, ca, tls.RequireAndVerifyClientCert, true)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certPEM))

	assert.NoError(t, probeMasterWithClientCert(address, ca.issueClientCert(t), roots))
}

// TestProbeMasterWithClientCert_AcceptedWhenMasterSilent verifies a master
// that accepts the certificate but sends nothing is still treated as
// acceptance once the silence window elapses.
func TestProbeMasterWithClientCert_AcceptedWhenMasterSilent(t *testing.T) {
	ca := newTestCA(t)
	address := startMTLSListener(t, ca, tls.RequireAndVerifyClientCert, false)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certPEM))

	assert.NoError(t, probeMasterWithClientCert(address, ca.issueClientCert(t), roots))
}

// TestProbeMasterWithClientCert_Rejected verifies the probe reports failure
// when the master does not trust the presented client certificate. The
// rejection arrives as a TLS alert after the handshake, which is precisely
// what the probe's post-handshake read exists to catch.
func TestProbeMasterWithClientCert_Rejected(t *testing.T) {
	master := newTestCA(t)
	address := startMTLSListener(t, master, tls.RequireAndVerifyClientCert, true)

	// A certificate from a different authority the master does not trust.
	stranger := newTestCA(t)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(master.certPEM))

	assert.Error(t, probeMasterWithClientCert(address, stranger.issueClientCert(t), roots))
}

// TestProbeMasterWithClientCert_Unreachable verifies a closed port is
// reported rather than treated as acceptance.
func TestProbeMasterWithClientCert_Unreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	ca := newTestCA(t)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certPEM))

	assert.Error(t, probeMasterWithClientCert(address, ca.issueClientCert(t), roots))
}

// TestProbeMasterWithClientCert_InvalidAddress verifies a malformed address
// is rejected before dialing.
func TestProbeMasterWithClientCert_InvalidAddress(t *testing.T) {
	ca := newTestCA(t)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca.certPEM))

	assert.Error(t, probeMasterWithClientCert("no-port", ca.issueClientCert(t), roots))
}

// --- command metadata ---

// TestDeviceEnrollCmd_Flags verifies the enroll command declares the flags
// the enrollment path reads.
func TestDeviceEnrollCmd_Flags(t *testing.T) {
	for _, name := range []string{"server", "code", "name", "cert-profile", "validity-days"} {
		assert.NotNil(t, deviceEnrollCmd.Flags().Lookup(name), "missing flag %q", name)
	}
	assert.Equal(t, agent.CertProfileDefault, deviceEnrollCmd.Flags().Lookup("cert-profile").DefValue)
}

// TestDeviceEnrollCmd_HelpDescribesRealBehavior verifies the help text
// describes certificate issuance rather than only preparing a request.
func TestDeviceEnrollCmd_HelpDescribesRealBehavior(t *testing.T) {
	assert.Contains(t, deviceEnrollCmd.Long, "certificate authority")
	assert.Contains(t, deviceEnrollCmd.Long, deviceEnrollCertFile)
	assert.NotContains(t, deviceEnrollCmd.Long, "pending enrollment completion")
}
