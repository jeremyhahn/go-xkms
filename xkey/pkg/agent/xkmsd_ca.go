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

package agent

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// xkmsd certificate authority errors.
var (
	// ErrCASignFailed indicates the certificate authority rejected or
	// failed to sign an agent CSR.
	ErrCASignFailed = errors.New("agent: certificate authority failed to sign the agent CSR")

	// ErrCACertFailed indicates the CA certificate could not be
	// retrieved from the certificate authority.
	ErrCACertFailed = errors.New("agent: failed to retrieve the CA certificate")

	// ErrCARevokeFailed indicates a certificate revocation request was
	// rejected or failed.
	ErrCARevokeFailed = errors.New("agent: certificate authority failed to revoke the certificate")

	// ErrCARevocationCheckFailed indicates the certificate authority
	// could not answer whether a certificate is revoked. Callers must
	// treat this as a rejection, never as "not revoked".
	ErrCARevocationCheckFailed = errors.New("agent: certificate authority failed to report revocation status")

	// ErrCAEmptyResponse indicates the certificate authority answered
	// successfully but returned no certificate material.
	ErrCAEmptyResponse = errors.New("agent: certificate authority returned no certificate")
)

const (
	// CAOperationTimeout bounds a single certificate authority call made
	// on behalf of an enrolling agent.
	CAOperationTimeout = 30 * time.Second

	// CertProfileDefault is the CA profile used for agent client
	// certificates. Agents authenticate to the master with mTLS, so they
	// receive client certificates.
	CertProfileDefault = "client"

	// RevocationReasonCessationOfOperation is the RFC 5280 §5.3.1 reason
	// code recorded when an agent certificate is revoked: the agent has
	// ceased operation.
	RevocationReasonCessationOfOperation = 5
)

// CARefusalError carries the message an xkmsd certificate authority
// returned when it answered a request but refused to carry it out.
type CARefusalError struct {
	// Message is the authority's explanation, or a generic one when it
	// gave none.
	Message string
}

// Error returns the authority's refusal message.
func (e *CARefusalError) Error() string {
	return e.Message
}

// XKMSdCA issues agent certificates through the xkmsd certificate
// authority reached over the xkms SDK transport. It is the CAService every
// xkey entry point - CLI and GUI alike - enrolls agents with; xkey holds no
// CA key of its own and never synthesizes certificate material.
//
// Thread-safe: yes. The SDK transport client is safe for concurrent use
// and no mutable state is kept here.
type XKMSdCA struct {
	// client is the connected SDK transport client.
	client transport.Client

	// profile is the CA certificate profile requested for agent CSRs.
	profile string

	// validityDays overrides the CA's default validity when positive.
	validityDays int

	// timeout bounds each certificate authority call.
	timeout time.Duration
}

// XKMSdCA satisfies the enrollment service's CA contract.
var _ CAService = (*XKMSdCA)(nil)

// NewXKMSdCA returns a CAService that signs, revokes and checks agent
// certificates through client. An empty profile selects
// CertProfileDefault; a validityDays of zero keeps the CA's default
// validity. The caller keeps ownership of client: Close releases it only
// for callers that connected it for this CA alone.
func NewXKMSdCA(client transport.Client, profile string, validityDays int) (*XKMSdCA, error) {
	if client == nil {
		return nil, &AgentError{Operation: "new_xkmsd_ca", Err: ErrNilClient}
	}
	if profile == "" {
		profile = CertProfileDefault
	}
	return &XKMSdCA{
		client:       client,
		profile:      profile,
		validityDays: validityDays,
		timeout:      CAOperationTimeout,
	}, nil
}

// Close releases the underlying transport client.
func (c *XKMSdCA) Close() error {
	return c.client.Close()
}

// SignCSR signs a PEM-encoded PKCS#10 certificate signing request with the
// xkmsd certificate authority and returns the issued certificate followed
// by its issuer chain, so an enrolling agent receives a complete chain.
func (c *XKMSdCA) SignCSR(csrPEM []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      c.profile,
		ValidityDays: c.validityDays,
	})
	if err != nil {
		return nil, &AgentError{Operation: "ca_sign_csr", Err: ErrCASignFailed, Cause: err}
	}
	if len(resp.CertificatePEM) == 0 {
		return nil, &AgentError{Operation: "ca_sign_csr", Err: ErrCAEmptyResponse}
	}

	certPEM := make([]byte, 0, len(resp.CertificatePEM)+len(resp.ChainPEM))
	certPEM = append(certPEM, resp.CertificatePEM...)
	certPEM = append(certPEM, resp.ChainPEM...)
	return certPEM, nil
}

// GetCACertificate returns the PEM-encoded certificate of the issuing
// authority, which enrolling agents pin as their trust anchor.
func (c *XKMSdCA) GetCACertificate() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	if err != nil {
		return nil, &AgentError{Operation: "ca_certificate", Err: ErrCACertFailed, Cause: err}
	}
	if len(resp.CertificatePEM) == 0 {
		return nil, &AgentError{Operation: "ca_certificate", Err: ErrCAEmptyResponse}
	}
	return resp.CertificatePEM, nil
}

// RevokeCertificate revokes an agent certificate by serial number,
// recording the RFC 5280 cessation-of-operation reason.
func (c *XKMSdCA) RevokeCertificate(serialNumber string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: serialNumber,
		Reason:       RevocationReasonCessationOfOperation,
	})
	if err != nil {
		return &AgentError{Operation: "ca_revoke_certificate", Err: ErrCARevokeFailed, Cause: err}
	}
	if !resp.Success {
		refusal := &CARefusalError{Message: resp.Message}
		if refusal.Message == "" {
			refusal.Message = "the certificate authority reported failure"
		}
		return &AgentError{Operation: "ca_revoke_certificate", Err: ErrCARevokeFailed, Cause: refusal}
	}
	return nil
}

// IsRevoked reports whether the certificate identified by its serial
// number has been revoked, consulting the xkmsd certificate authority's
// revocation state directly rather than fetching and parsing a CRL.
func (c *XKMSdCA) IsRevoked(serialNumber string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.IsRevoked(ctx, &transport.IsRevokedRequest{
		SerialNumber: serialNumber,
	})
	if err != nil {
		return false, &AgentError{Operation: "ca_is_revoked", Err: ErrCARevocationCheckFailed, Cause: err}
	}
	return resp.Revoked, nil
}
