// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import (
	"context"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
)

const certificateService = "admin.certificate"

// CertificateClient provides admin certificate management operations.
type CertificateClient interface {
	// List lists certificates with optional filtering.
	List(ctx context.Context, req *ListCertificatesRequest) (*ListCertificatesResponse, error)

	// Get retrieves a certificate by serial number.
	Get(ctx context.Context, serial string) (*CertificateInfo, error)

	// Revoke revokes a certificate by serial number with an optional reason.
	Revoke(ctx context.Context, serial, reason string) error
}

type certificateClient struct {
	transport transport.Transport
}

func newCertificateClient(t transport.Transport) CertificateClient {
	return &certificateClient{transport: t}
}

// certificateSerialRequest wraps a serial number for transport serialization.
type certificateSerialRequest struct {
	Serial string `json:"serial"`
}

// revokeCertificateTransportRequest wraps the serial number and reason for transport.
type revokeCertificateTransportRequest struct {
	Serial string `json:"serial"`
	Reason string `json:"reason,omitempty"`
}

func (c *certificateClient) List(ctx context.Context, req *ListCertificatesRequest) (*ListCertificatesResponse, error) {
	if req == nil {
		req = &ListCertificatesRequest{}
	}

	raw, err := c.transport.Request(ctx, certificateService, "list", req)
	if err != nil {
		return nil, err
	}

	var certs []*CertificateInfo
	var pagination *Pagination
	if err := mapListResponse(raw, "certificates", &certs, &pagination); err != nil {
		return nil, err
	}

	return &ListCertificatesResponse{
		Certificates: certs,
		Pagination:   pagination,
	}, nil
}

func (c *certificateClient) Get(ctx context.Context, serial string) (*CertificateInfo, error) {
	if serial == "" {
		return nil, errors.NewInvalidInput("admin.certificate.Get", "serial number cannot be empty")
	}

	raw, err := c.transport.Request(ctx, certificateService, "get", &certificateSerialRequest{Serial: serial})
	if err != nil {
		return nil, err
	}

	var result CertificateInfo
	if err := mapResponse(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *certificateClient) Revoke(ctx context.Context, serial, reason string) error {
	if serial == "" {
		return errors.NewInvalidInput("admin.certificate.Revoke", "serial number cannot be empty")
	}

	_, err := c.transport.Request(ctx, certificateService, "revoke", &revokeCertificateTransportRequest{
		Serial: serial,
		Reason: reason,
	})
	return err
}
