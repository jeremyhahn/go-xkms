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

package clusterca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const (
	// nodeCertFile caches this node's issued certificate chain
	// (leaf first, then intermediates), PEM-encoded.
	nodeCertFile = "node-cert.pem"

	// anchorCertFile caches the cluster trust-anchor bundle (certificates
	// only — never key material). On the first node this is the CA bundle
	// (root + intermediates) the runtime CA imports during adoption.
	anchorCertFile = "anchor.pem"

	// renewalFraction is the fraction of remaining validity below which a
	// cached node certificate is re-enrolled at boot (remaining < 1/4 of
	// total validity).
	renewalFraction = 4
)

// AnchorCachePath returns the path of the cached trust-anchor bundle beneath
// dataDir (the cluster trust anchor advertised to joining nodes).
func AnchorCachePath(dataDir string) string {
	return filepath.Join(dataDir, anchorCertFile)
}

// stagedCACertsFile holds the FULL first-node CA certificate set (root + every
// intermediate), which the runtime CA adopts before Load — unlike the anchor
// bundle, which carries only the root + selected issuing intermediate.
const stagedCACertsFile = "ca-certs.pem"

// StagedCACertsPath returns the path of the first node's full CA certificate
// set beneath dataDir. The composition root (initializeCA) reads this to adopt
// the pre-staged CA hierarchy into the runtime certificate store so Load — which
// verifies every configured intermediate — succeeds without re-running Init.
func StagedCACertsPath(dataDir string) string {
	return filepath.Join(dataDir, stagedCACertsFile)
}

// loadCachedIdentity returns the cached node certificate chain and trust
// anchor, or ok=false when either is absent.
func (p *Provisioner) loadCachedIdentity() (leafChainPEM, anchorPEM []byte, ok bool) {
	leafChainPEM, err := os.ReadFile(filepath.Join(p.opts.DataDir, nodeCertFile))
	if err != nil {
		return nil, nil, false
	}
	anchorPEM, err = os.ReadFile(filepath.Join(p.opts.DataDir, anchorCertFile))
	if err != nil {
		return nil, nil, false
	}
	return leafChainPEM, anchorPEM, true
}

// cacheIdentity persists the node certificate chain and trust anchor so
// restarts reuse them. Only public material is written.
func (p *Provisioner) cacheIdentity(leafChainPEM, anchorPEM []byte) error {
	if err := os.MkdirAll(p.opts.DataDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(p.opts.DataDir, nodeCertFile), leafChainPEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(p.opts.DataDir, anchorCertFile), anchorPEM, 0o600)
}

// parseChainPEM decodes a PEM chain into the leaf (first certificate) and
// any following intermediates.
func parseChainPEM(pemBytes []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("clusterca: no certificates in PEM chain")
	}
	return certs[0], certs[1:], nil
}

// certsToPEM encodes certificates as a concatenated PEM bundle.
func certsToPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return out
}

// needsRenewal reports whether the certificate is expired or inside the
// renewal window (less than 1/renewalFraction of its validity remaining).
func needsRenewal(cert *x509.Certificate, now time.Time) bool {
	if now.After(cert.NotAfter) {
		return true
	}
	total := cert.NotAfter.Sub(cert.NotBefore)
	remaining := cert.NotAfter.Sub(now)
	return remaining < total/renewalFraction
}

// anchorIntermediates returns the non-self-signed certificates from the
// anchor bundle — the issuing intermediates a node presents alongside its
// leaf so peers can build the chain to the root.
func anchorIntermediates(anchorPEM []byte) []*x509.Certificate {
	var intermediates []*x509.Certificate
	rest := anchorPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if cert.CheckSignatureFrom(cert) != nil {
			intermediates = append(intermediates, cert)
		}
	}
	return intermediates
}
