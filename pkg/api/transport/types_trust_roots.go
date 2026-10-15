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

package transport

// TrustRoot is one certificate of the platform trust-root store
// (pkg/attestation/truststore).
type TrustRoot struct {
	// Fingerprint is the lowercase hex SHA-256 of the DER certificate.
	Fingerprint string `json:"fingerprint"`

	// Purpose is the root's classification: "general", "user-ca",
	// "bootstrap-ca", "tpm-manufacturer", "android-hardware",
	// "idevid-issuer", "image-signer", or "synced" for a quarantined root.
	Purpose string `json:"purpose"`

	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Algorithm string `json:"algorithm"`

	// NotBefore, NotAfter and AddedAt are RFC 3339 timestamps in UTC.
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	AddedAt   string `json:"added_at"`

	// Source records where the root came from, when known.
	Source string `json:"source,omitempty"`

	// PEM is the certificate. TrustRootGet sets it; TrustRootList leaves it
	// empty.
	PEM string `json:"pem,omitempty"`
}

// TrustRootListRequest filters the roots TrustRootList returns.
type TrustRootListRequest struct {
	// Purpose, when set, keeps only the roots of that purpose.
	Purpose string `json:"purpose,omitempty"`
}

// TrustRootListResponse lists trust roots, sorted by subject.
type TrustRootListResponse struct {
	Roots []TrustRoot `json:"roots"`
}

// TrustRootRequest names one trust root, for TrustRootGet,
// TrustRootQuarantine and TrustRootRemove.
type TrustRootRequest struct {
	// Fingerprint is the lowercase hex SHA-256 of the DER certificate.
	Fingerprint string `json:"fingerprint"`
}

// TrustRootImportRequest imports the certificates of a PEM bundle.
type TrustRootImportRequest struct {
	// PEM holds one or more CERTIFICATE blocks.
	PEM string `json:"pem"`

	// Purpose, when set, classifies every certificate of the bundle;
	// empty classifies each certificate from its contents.
	Purpose string `json:"purpose,omitempty"`

	// Source records where the bundle came from.
	Source string `json:"source,omitempty"`
}

// TrustRootImportResponse counts the certificates an import added and the
// ones it skipped because the store already held them.
type TrustRootImportResponse struct {
	Added   int `json:"added"`
	Skipped int `json:"skipped"`
}
