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

//go:build codec_json

package handlers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"log/slog"
	"testing"
)

// issuerCapableCA embeds MockCA (a full ca.TCGCA) and additionally implements
// ca.IdentityIssuer so clusterIssuerOverride's type-assertion succeeds. It
// records the CN it was asked to issue for.
type issuerCapableCA struct {
	*MockCA
	requestedCN string
	signer      crypto.Signer
	cert        *x509.Certificate
	err         error
}

func (c *issuerCapableCA) IssuerForIdentity(_ context.Context, cn string) (crypto.Signer, *x509.Certificate, error) {
	c.requestedCN = cn
	return c.signer, c.cert, c.err
}

func newTestSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// TestClusterIssuerOverride_NotConfigured verifies that with no ClusterCACN the
// override is a no-op (nil signer/cert, no error): default issuance is used.
func TestClusterIssuerOverride_NotConfigured(t *testing.T) {
	s := &RestService{ca: &MockCA{}, logger: slog.Default()}
	signer, cert, err := s.clusterIssuerOverride(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signer != nil || cert != nil {
		t.Errorf("expected (nil, nil), got signer=%v cert=%v", signer, cert)
	}
}

// TestClusterIssuerOverride_Unsupported verifies fail-closed behavior: a
// configured cluster CN with a CA that does not implement ca.IdentityIssuer
// returns ErrClusterIssuerUnsupported rather than silently using the default.
func TestClusterIssuerOverride_Unsupported(t *testing.T) {
	s := &RestService{ca: &MockCA{}, clusterCACN: "Cluster CA", logger: slog.Default()}
	_, _, err := s.clusterIssuerOverride(context.Background())
	if !errors.Is(err, ErrClusterIssuerUnsupported) {
		t.Fatalf("expected ErrClusterIssuerUnsupported, got %v", err)
	}
}

// TestClusterIssuerOverride_Resolves verifies that a configured cluster CN is
// resolved through the CA's IdentityIssuer seam and the returned signer/cert
// are propagated (they become the external issuer on the CertificateRequest).
func TestClusterIssuerOverride_Resolves(t *testing.T) {
	signer := newTestSigner(t)
	cert := &x509.Certificate{}
	ca := &issuerCapableCA{MockCA: &MockCA{}, signer: signer, cert: cert}
	s := &RestService{ca: ca, clusterCACN: "Cluster CA", logger: slog.Default()}

	gotSigner, gotCert, err := s.clusterIssuerOverride(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ca.requestedCN != "Cluster CA" {
		t.Errorf("IssuerForIdentity called with %q, want \"Cluster CA\"", ca.requestedCN)
	}
	if gotSigner != signer {
		t.Error("returned signer is not the cluster issuer signer")
	}
	if gotCert != cert {
		t.Error("returned cert is not the cluster issuer certificate")
	}
}

// TestClusterIssuerOverride_ResolveError verifies that an error resolving the
// configured cluster issuer propagates (issuance fails closed).
func TestClusterIssuerOverride_ResolveError(t *testing.T) {
	wantErr := errors.New("no such identity")
	ca := &issuerCapableCA{MockCA: &MockCA{}, err: wantErr}
	s := &RestService{ca: ca, clusterCACN: "Missing CA", logger: slog.Default()}

	_, _, err := s.clusterIssuerOverride(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the resolve error to propagate, got %v", err)
	}
}
