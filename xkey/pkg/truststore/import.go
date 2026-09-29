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

package truststore

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
)

// ImportResult reports the outcome of importing a PEM bundle.
//
// Added alone cannot tell an operator what happened: "0 added" is the same
// number whether the bundle was empty, unparseable, or already entirely
// present. Skipped names the last of those three explicitly.
type ImportResult struct {
	// Added counts the certificates written to the store.
	Added int

	// Skipped counts the certificates already present in the store.
	Skipped int
}

// certificateImporter is the single-certificate write path every store
// implementation provides. Importing a bundle is the same algorithm over it,
// so it lives here once rather than once per store.
type certificateImporter interface {
	AddCertificateWithOptions(cert *x509.Certificate, opts *AddCertificateOptions) error
}

// importPEM parses pemData and adds every certificate it contains through
// store, applying opts as metadata (a nil opts auto-classifies the purpose).
// Certificates already present are counted as skipped rather than failing the
// import. A bundle containing no parseable certificate is an error: silently
// reporting nothing added would be indistinguishable from a successful import
// of a file whose contents were already known.
func importPEM(store certificateImporter, pemData []byte, opts *AddCertificateOptions) (ImportResult, error) {
	var result ImportResult

	if len(pemData) == 0 {
		return result, ErrInvalidCertificate
	}

	certs, err := parsePEMCertificates(pemData)
	if err != nil {
		return result, err
	}

	for _, cert := range certs {
		addErr := store.AddCertificateWithOptions(cert, opts)
		if errors.Is(addErr, ErrCertificateExists) {
			result.Skipped++
			continue
		}
		if addErr != nil {
			return result, addErr
		}
		result.Added++
	}

	return result, nil
}

// bootstrapSourcePrefix labels the source of every certificate fetched from
// a server, matching the provenance the platform CA bundle fetcher reports.
const bootstrapSourcePrefix = "platform:"

// BootstrapImportOptions returns the metadata a CA bundle fetched from server
// over the network is filed under: PurposeBootstrapCA, with the server's host
// recorded as its source.
//
// Every network bootstrap path files through it ("xkey trust fetch", "xkey
// trust bootstrap", and the GUI's trust-strap import) so a fetched bundle
// lands in the same place whichever surface fetched it. It is never
// auto-classified: the server chose the bundle, and auto-classification would
// let it file a certificate as an attestation anchor (#1312).
//
// server is a URL ("https://kms.example.com:8443") or, for Noise, a bare
// host:port; the source records the URL's host, or server itself when it has
// no URL host.
func BootstrapImportOptions(server string) *AddCertificateOptions {
	return &AddCertificateOptions{
		Purpose: PurposeBootstrapCA,
		Source:  bootstrapSourcePrefix + bootstrapHost(server),
	}
}

// bootstrapHost extracts the host[:port] a bootstrap server string names.
func bootstrapHost(server string) string {
	server = strings.TrimSpace(server)
	if parsed, err := url.Parse(server); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return server
}

// purposeLister is the purpose-scoped read path every store implementation
// provides.
type purposeLister interface {
	CertificatesByPurpose(purpose CertPurpose) ([]*x509.Certificate, error)
}

// tlsAnchorPurposes are the purposes whose certificates may anchor a TLS
// server chain: the CAs an operator added for a deployment.
//
// The attestation purposes (tpm-manufacturer, android-hardware,
// idevid-issuer) are deliberately absent. They anchor device attestation
// chains, and a TLS session to a server is not one; promoting them to TLS
// roots would widen what a TPM vendor root can authenticate. PurposeSynced is
// absent too: a certificate a paired device pushed is never an anchor.
var tlsAnchorPurposes = []CertPurpose{PurposeUserCA, PurposeBootstrapCA, PurposeGeneral}

// tlsRoots collects the store's TLS-eligible anchors.
func tlsRoots(store purposeLister) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	for _, purpose := range tlsAnchorPurposes {
		certs, err := store.CertificatesByPurpose(purpose)
		if err != nil {
			return nil, err
		}
		roots = append(roots, certs...)
	}
	return roots, nil
}
