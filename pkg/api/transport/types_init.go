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

package transport

import (
	"encoding/json"
	"time"
)

// Init Ceremony types

// InitStatusResponse contains the current init ceremony state.
type InitStatusResponse struct {
	State string `json:"state"`
}

// ClaimCertBeginRequest contains parameters for beginning a certificate claim.
type ClaimCertBeginRequest struct {
	Username string `json:"username"`
}

// ClaimCertBeginResponse contains the challenge for a certificate claim.
type ClaimCertBeginResponse struct {
	Nonce     string    `json:"nonce"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ClaimCertCompleteRequest contains parameters for completing a certificate claim.
type ClaimCertCompleteRequest struct {
	Username  string `json:"username"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"` // base64-encoded
}

// ClaimCertCompleteResponse contains the issued certificate from a completed claim.
type ClaimCertCompleteResponse struct {
	CertPEM   string `json:"cert_pem"`
	CACertPEM string `json:"ca_cert_pem"`
}

// ClaimShareRequest contains parameters for claiming a Shamir share.
type ClaimShareRequest struct {
	Username string `json:"username"`
}

// ClaimShareResponse contains the claimed Shamir share.
type ClaimShareResponse struct {
	Share json.RawMessage `json:"share"`
}

// SignCSRInitRequest contains parameters for SO-authorized CSR signing during init.
type SignCSRInitRequest struct {
	Username string `json:"username"`
	SOPin    string `json:"so_pin"`
	CSRPEM   string `json:"csr_pem"`
	Role     string `json:"role"`
}

// SignCSRInitResponse contains the signed certificate from init CSR signing.
type SignCSRInitResponse struct {
	CertPEM string `json:"cert_pem"`
}

// Credential Management types

// CredentialSubmitRequest contains parameters for submitting a credential.
type CredentialSubmitRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"` // base64-encoded
}

// CredentialSubmitResponse contains the result of a credential submission.
type CredentialSubmitResponse struct {
	Status string `json:"status"`
}

// CredentialStrategyResponse contains the configured credential strategy.
type CredentialStrategyResponse struct {
	Strategy   string `json:"strategy"`
	AutoUnseal bool   `json:"auto_unseal"`
}
