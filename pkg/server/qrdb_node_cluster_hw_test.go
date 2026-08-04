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

//go:build raft

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	clusterenroll "github.com/jeremyhahn/go-qrdb/sdk/go/clusterenroll"
	clustertls "github.com/jeremyhahn/go-qrdb/sdk/go/clustertls"
)

// TestSignerCertificate verifies the hardware-enroller assembly: a node leaf
// issued from the cluster CA for a backend-held key's public part, combined with
// the signer into a tls.Certificate that chains to the CA and carries the node's
// public key. A software ECDSA key stands in for the hardware key — the seam only
// needs a crypto.Signer, and the private key never enters the certificate bytes.
func TestSignerCertificate(t *testing.T) {
	caMat, err := clustertls.GenerateCABundle()
	if err != nil {
		t.Fatalf("GenerateCABundle: %v", err)
	}

	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("node key: %v", err)
	}

	nodeURI := clusterenroll.NodeURI("xkms.cluster", "10.0.0.1:63001")
	leafPEM, err := clustertls.IssueLeafForKey(caMat.CACertPEM, caMat.CAKeyPEM, nodeKey.Public(), nodeURI)
	if err != nil {
		t.Fatalf("IssueLeafForKey: %v", err)
	}

	cert, err := signerCertificate(leafPEM, nodeKey)
	if err != nil {
		t.Fatalf("signerCertificate: %v", err)
	}
	if cert.PrivateKey == nil {
		t.Fatal("certificate has no signer PrivateKey")
	}
	if cert.Leaf == nil || len(cert.Certificate) != 1 {
		t.Fatal("certificate missing parsed leaf or DER chain")
	}

	// The leaf must chain to the cluster CA.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caMat.CACertPEM) {
		t.Fatal("append CA to pool")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("leaf does not chain to cluster CA: %v", err)
	}

	// The leaf must carry the node key's public part (so the signer matches).
	leafPub, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafPub.Equal(nodeKey.Public()) {
		t.Fatal("leaf public key does not match the node signer")
	}

	// Malformed leaf PEM must fail closed.
	if _, err := signerCertificate([]byte("not a pem block"), nodeKey); err == nil {
		t.Fatal("expected error on malformed leaf PEM")
	}
}
