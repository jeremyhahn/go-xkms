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

package peergate_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// pki is a one-level test CA that issues the server, client, device identity
// and attestation key certificates the tests use.
type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "peergate test root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &pki{cert: cert, key: key, pool: pool}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

var serialCounter = struct {
	sync.Mutex
	next int64
}{next: 100}

func nextSerial() *big.Int {
	serialCounter.Lock()
	defer serialCounter.Unlock()
	serialCounter.next++
	return big.NewInt(serialCounter.next)
}

func (p *pki) issue(t *testing.T, tmpl *x509.Certificate, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = nextSerial()
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(12 * time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, pub, p.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// device names the TPM a DevID-class certificate is issued for. The zero
// value issues a certificate that names no TPM.
type device struct {
	serial string
	permID string
}

// deviceSAN is the TCG DevID §8.1 subjectAltName naming d.
func deviceSAN(t *testing.T, d device) pkix.Extension {
	t.Helper()
	hardware, err := ca.MarshalHardwareModuleName(ca.OIDTCGHwTypeTPM2, []byte(d.serial))
	require.NoError(t, err)
	permanent, err := ca.MarshalPermanentIdentifier(d.permID, ca.OIDTCGOnEKPermIdSha256)
	require.NoError(t, err)
	ext, err := ca.BuildSubjectAltName(pkix.Name{CommonName: "device"}, nil, nil, nil, nil, []ca.OtherName{
		{TypeID: ca.OIDHardwareModuleName, Value: hardware},
		{TypeID: ca.OIDPermanentIdentifier, Value: permanent},
	}, nil)
	require.NoError(t, err)
	return ext
}

// clientCert issues a TLS client certificate. With a device it is an IDevID
// for that TPM; without one it is an ordinary client certificate.
func (p *pki) clientCert(t *testing.T, d device) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "peer", OrganizationalUnit: []string{"system"}},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if d.serial != "" {
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{ca.OIDTCGVerifiedTPMFixed}
		tmpl.Policies = []x509.OID{ca.TCGVerifiedTPMFixedPolicy}
		tmpl.ExtraExtensions = []pkix.Extension{deviceSAN(t, d)}
	}
	cert := p.issue(t, tmpl, &key.PublicKey)
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}, cert
}

// akCert issues a Restricted attestation key certificate for pub, naming d
// when d names a TPM, and returns it PEM encoded.
func (p *pki) akCert(t *testing.T, pub crypto.PublicKey, d device) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "iak"},
		KeyUsage: x509.KeyUsageDigitalSignature,
		Policies: []x509.OID{ca.TCGVerifiedTPMRestrictedPolicy},
	}
	if d.serial != "" {
		tmpl.ExtraExtensions = []pkix.Extension{deviceSAN(t, d)}
	}
	cert := p.issue(t, tmpl, pub)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// connection is both ends of one completed mutual-TLS handshake.
type connection struct {
	server *tls.ConnectionState
	client *tls.ConnectionState
}

// connect completes a TLS 1.3 handshake over an in-memory pipe, the server
// requiring and verifying a client certificate from p.
func (p *pki) connect(t *testing.T, client tls.Certificate) connection {
	t.Helper()
	serverKey := newKey(t)
	serverCert := p.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "localhost"},
		DNSNames:    []string{"localhost"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &serverKey.PublicKey)

	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() {
		require.NoError(t, serverEnd.Close())
		require.NoError(t, clientEnd.Close())
	})
	server := tls.Server(serverEnd, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.pool,
		MinVersion:   tls.VersionTLS13,
	})
	clientConn := tls.Client(clientEnd, &tls.Config{
		Certificates: []tls.Certificate{client},
		RootCAs:      p.pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var serverErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = server.HandshakeContext(ctx)
	}()
	clientErr := clientConn.HandshakeContext(ctx)
	wg.Wait()
	require.NoError(t, serverErr)
	require.NoError(t, clientErr)

	serverState := server.ConnectionState()
	clientState := clientConn.ConnectionState()
	return connection{server: &serverState, client: &clientState}
}

// goldenPCRs is the measured state the baseline accepts.
func goldenPCRs() map[int][]byte {
	return map[int][]byte{
		0:  fill(0x10),
		7:  fill(0x17),
		10: fill(0x1a),
	}
}

func fill(b byte) []byte {
	out := make([]byte, sha256.Size)
	for i := range out {
		out[i] = b
	}
	return out
}

// attestationKey is a software stand-in for a TPM's IAK: it signs quotes the
// way TPM2_Quote does.
type attestationKey struct {
	key *ecdsa.PrivateKey
	pem []byte
}

func (p *pki) newAK(t *testing.T, d device) attestationKey {
	t.Helper()
	key := newKey(t)
	return attestationKey{key: key, pem: p.akCert(t, &key.PublicKey, d)}
}

// quote marshals a TPMS_ATTEST over pcrs with the qualifying data and signs
// it, returning the attest structure and its ASN.1 ECDSA signature.
func (a attestationKey) quote(t *testing.T, qualifying []byte, pcrs map[int][]byte) ([]byte, []byte) {
	t.Helper()
	indices := make([]int, 0, len(pcrs))
	for idx := range pcrs {
		indices = append(indices, idx)
	}
	sort.Ints(indices)
	h := sha256.New()
	selection := make([]uint, 0, len(indices))
	for _, idx := range indices {
		h.Write(pcrs[idx])
		selection = append(selection, uint(idx))
	}
	attest := gotpm.Marshal(gotpm.TPMSAttest{
		Magic:           gotpm.TPMGeneratedValue,
		Type:            gotpm.TPMSTAttestQuote,
		QualifiedSigner: gotpm.TPM2BName{Buffer: []byte("test-ak")},
		ExtraData:       gotpm.TPM2BData{Buffer: qualifying},
		Attested: gotpm.NewTPMUAttest(gotpm.TPMSTAttestQuote, &gotpm.TPMSQuoteInfo{
			PCRSelect: gotpm.TPMLPCRSelection{PCRSelections: []gotpm.TPMSPCRSelection{{
				Hash:      gotpm.TPMAlgSHA256,
				PCRSelect: gotpm.PCClientCompatible.PCRs(selection...),
			}}},
			PCRDigest: gotpm.TPM2BDigest{Buffer: h.Sum(nil)},
		}),
	})
	digest := sha256.Sum256(attest)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	require.NoError(t, err)
	return attest, signature
}

// evidence is what an honest peer submits: a quote over pcrs bound to the
// connection it is submitted on.
func (a attestationKey) evidence(t *testing.T, conn connection, nonce []byte, pcrs map[int][]byte) peer.Evidence {
	t.Helper()
	qualifying, err := peer.QualifyingDataFromTLS(conn.client, nonce)
	require.NoError(t, err)
	attest, signature := a.quote(t, qualifying, pcrs)
	return peer.Evidence{
		Quote:            attest,
		Signature:        signature,
		Nonce:            nonce,
		PCRs:             pcrs,
		AKCertificatePEM: a.pem,
	}
}
