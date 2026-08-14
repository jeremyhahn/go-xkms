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
	"context"
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
)

// Agent certificate authority errors.
var (
	// ErrAgentCAUnavailable indicates no xkmsd certificate authority could
	// be reached. Agent enrollment issues real client certificates, so the
	// agent server refuses to start without one.
	ErrAgentCAUnavailable = errors.New("agent: enrollment requires a reachable xkmsd certificate authority; " +
		"set --xkmsd-url or XKMSD_URL (xkey never signs certificates locally)")

	// ErrAgentCASignFailed indicates the certificate authority rejected or
	// failed to sign an agent CSR.
	ErrAgentCASignFailed = errors.New("agent: certificate authority failed to sign the agent CSR")

	// ErrAgentCACertFailed indicates the CA certificate could not be
	// retrieved from the certificate authority.
	ErrAgentCACertFailed = errors.New("agent: failed to retrieve the CA certificate")

	// ErrAgentCARevokeFailed indicates a certificate revocation request was
	// rejected or failed.
	ErrAgentCARevokeFailed = errors.New("agent: certificate authority failed to revoke the certificate")

	// ErrAgentCAEmptyResponse indicates the certificate authority answered
	// successfully but returned no certificate material.
	ErrAgentCAEmptyResponse = errors.New("agent: certificate authority returned no certificate")
)

const (
	// agentCAOperationTimeout bounds a single certificate authority call
	// made on behalf of an enrolling agent.
	agentCAOperationTimeout = 30 * time.Second

	// agentCertProfileDefault is the CA profile used for agent client
	// certificates. Agents authenticate to the master with mTLS, so they
	// receive client certificates.
	agentCertProfileDefault = "client"

	// agentRevocationReason is the RFC 5280 reason code recorded when an
	// agent certificate is revoked: the agent has ceased operation.
	agentRevocationReason = 5
)

// xkmsdCA issues agent certificates through the xkmsd certificate
// authority reached over the xkms SDK transport. It is the CAService the
// enrollment service signs with; xkey holds no CA key of its own and never
// synthesizes certificate material.
//
// Thread-safe: yes. The SDK transport client is safe for concurrent use
// and no mutable state is kept here.
type xkmsdCA struct {
	// client is the connected SDK transport client. The caller owns Close.
	client transport.Client

	// profile is the CA certificate profile requested for agent CSRs.
	profile string

	// validityDays overrides the CA's default validity when positive.
	validityDays int

	// timeout bounds each certificate authority call.
	timeout time.Duration
}

// xkmsdCA satisfies the enrollment service's CA contract.
var _ agent.CAService = (*xkmsdCA)(nil)

// newAgentCA connects to the configured xkmsd certificate authority and
// verifies it can serve agent enrollment by retrieving its CA certificate.
// It fails closed - returning ErrAgentCAUnavailable - when no server URL is
// configured, when the server cannot be reached, or when the server has no
// usable CA certificate. The returned CA owns a connected transport client
// that the caller must Close.
//
// The endpoint is resolved without consulting cmd so that "agent start
// --tls-ca", which supplies the agent server's own client-verification
// bundle, is never mistaken for the trust bundle used to reach xkmsd; that
// one comes from XKMSD_TLS_CA or the xkey config.
func newAgentCA(profile string, validityDays int) (*xkmsdCA, error) {
	client, err := connectXKMSdClient(nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: err}
	}

	ca := &xkmsdCA{
		client:       client,
		profile:      profile,
		validityDays: validityDays,
		timeout:      agentCAOperationTimeout,
	}

	// Prove the authority is usable before the listener accepts agents.
	if _, err := ca.GetCACertificate(); err != nil {
		if closeErr := ca.Close(); closeErr != nil {
			return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: closeErr}
		}
		return nil, &SentinelCauseError{Sentinel: ErrAgentCAUnavailable, Cause: err}
	}
	return ca, nil
}

// Close releases the underlying transport client.
func (c *xkmsdCA) Close() error {
	if c.client == nil {
		return nil
	}
	return c.client.Close()
}

// SignCSR signs a PEM-encoded PKCS#10 certificate signing request with the
// xkmsd certificate authority and returns the issued certificate followed
// by its issuer chain, so an enrolling agent receives a complete chain.
func (c *xkmsdCA) SignCSR(csrPEM []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:       csrPEM,
		Profile:      c.profile,
		ValidityDays: c.validityDays,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentCASignFailed, Cause: err}
	}
	if len(resp.CertificatePEM) == 0 {
		return nil, &DetailError{Err: ErrAgentCAEmptyResponse, Detail: ": no signed certificate in the CA response"}
	}

	certPEM := make([]byte, 0, len(resp.CertificatePEM)+len(resp.ChainPEM))
	certPEM = append(certPEM, resp.CertificatePEM...)
	certPEM = append(certPEM, resp.ChainPEM...)
	return certPEM, nil
}

// GetCACertificate returns the PEM-encoded certificate of the issuing
// authority, which enrolling agents pin as their trust anchor.
func (c *xkmsdCA) GetCACertificate() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.GetCACertificate(ctx, &transport.GetCACertificateRequest{})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrAgentCACertFailed, Cause: err}
	}
	if len(resp.CertificatePEM) == 0 {
		return nil, &DetailError{Err: ErrAgentCAEmptyResponse, Detail: ": no CA certificate in the CA response"}
	}
	return resp.CertificatePEM, nil
}

// RevokeCertificate revokes an agent certificate by serial number,
// recording the RFC 5280 cessation-of-operation reason.
func (c *xkmsdCA) RevokeCertificate(serialNumber string) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	resp, err := c.client.RevokeCertificate(ctx, &transport.RevokeCertificateRequest{
		SerialNumber: serialNumber,
		Reason:       agentRevocationReason,
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAgentCARevokeFailed, Cause: err}
	}
	if !resp.Success {
		detail := resp.Message
		if detail == "" {
			detail = "the certificate authority reported failure"
		}
		return &DetailError{Err: ErrAgentCARevokeFailed, Detail: ": " + detail}
	}
	return nil
}

// agentCertProfile returns the CA profile requested for agent
// certificates, falling back to the client profile.
func agentCertProfile(cmd *cobra.Command) string {
	profile, _ := cmd.Flags().GetString("cert-profile")
	if profile == "" {
		return agentCertProfileDefault
	}
	return profile
}
