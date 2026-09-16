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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chainCA is a TCGCA whose CABundle is whatever the test sets. Every other
// method is unimplemented: appendIssuingChain touches only CABundle.
type chainCA struct {
	ca.TCGCA
	bundle []byte
	err    error
}

func (c *chainCA) CABundle() ([]byte, error) { return c.bundle, c.err }

// issuingChainFixture returns a self-signed root, an intermediate it signed,
// and the PEM bundle a CA serves for them (intermediate first, then root).
func issuingChainFixture(t *testing.T) (root, intermediate *x509.Certificate, bundle []byte) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root-ca.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ca01.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	intermediate, err = x509.ParseCertificate(interDER)
	require.NoError(t, err)

	bundle = append(encodeCertificatePEM(interDER), encodeCertificatePEM(rootDER)...)
	return root, intermediate, bundle
}

func parsePEMChain(t *testing.T, b []byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		out = append(out, c)
	}
}

// TestAppendIssuingChain_AddsTheChainAfterTheLeaf is the RFC 8555 §7.4.2
// contract: application/pem-certificate-chain is the end-entity certificate
// FOLLOWED BY THE CHAIN. The finalize handler previously emitted leaves only
// while serving them under that media type, so a client holding nothing could
// not build a path to a trust anchor — and an enrolled device could not
// resolve the issuer of its own certificate at all.
func TestAppendIssuingChain_AddsTheChainAfterTheLeaf(t *testing.T) {
	root, intermediate, bundle := issuingChainFixture(t)
	svc := &RestService{ca: &chainCA{bundle: bundle}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// The end-entity DER is opaque to appendIssuingChain, so the intermediate
	// stands in for it here; what matters is that the chain lands AFTER it.
	body := svc.appendIssuingChain(encodeCertificatePEM(intermediate.Raw))
	got := parsePEMChain(t, body)

	require.Len(t, got, 3, "end-entity certificate plus the two-certificate chain")
	assert.Equal(t, "ca01.test", got[0].Subject.CommonName, "end-entity stays first")
	assert.Equal(t, "ca01.test", got[1].Subject.CommonName, "intermediate follows, leaf-ward first")
	assert.Equal(t, "root-ca.test", got[2].Subject.CommonName, "root terminates the chain")

	// The appended chain must actually verify the path, which is the whole
	// point of shipping it.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	_, err := got[1].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	require.NoError(t, err, "the served chain must chain to its own root")
}

// TestAppendIssuingChain_LeafOnlyWhenBundleUnavailable pins the deliberate
// degradation. The certificate is already signed when this runs, so a CA that
// cannot produce a bundle must not fail issuance: withholding a signed
// certificate is worse than serving a leaf-only body.
func TestAppendIssuingChain_LeafOnlyWhenBundleUnavailable(t *testing.T) {
	_, intermediate, _ := issuingChainFixture(t)
	leaf := encodeCertificatePEM(intermediate.Raw)

	for name, broken := range map[string]*chainCA{
		"error": {err: errors.New("bundle unavailable")},
		"empty": {bundle: nil},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &RestService{ca: broken, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			got := svc.appendIssuingChain(leaf)
			assert.Equal(t, leaf, got, "the end-entity body must be returned untouched, not an error")
			assert.Len(t, parsePEMChain(t, got), 1)
		})
	}
}
