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

package xkms

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ListPIVSlots returns the status of all PIV slots for the specified backend.
// Implements the PIVServicer interface.
func (s *XKMSService) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return ListPIVSlots(ctx, req)
}

// GetPIVCertificate retrieves a certificate from a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return GetPIVCertificate(ctx, req)
}

// StorePIVCertificate stores a certificate in a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return StorePIVCertificate(ctx, req)
}

// DeletePIVCertificate removes a certificate from a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return DeletePIVCertificate(ctx, req)
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
// Implements the PIVServicer interface.
func (s *XKMSService) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return GeneratePIVKey(ctx, req)
}

// ImportPIVCertificate imports a certificate into a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return ImportPIVCertificate(ctx, req)
}

// ExportPIVCertificate exports a certificate from a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return ExportPIVCertificate(ctx, req)
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
// Implements the PIVServicer interface.
func (s *XKMSService) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return GeneratePIVCSR(ctx, req)
}

// InitPIVBackendResolver configures the PIV manager to resolve key generators
// from registered XKMS backends. This enables PIV key generation using TPM2,
// PKCS11, and other configured backends instead of software-only generation.
func (s *XKMSService) InitPIVBackendResolver() error {
	resolver := func(backendName string) (PIVKeyGenerator, error) {
		b, err := GetBackend(backendName)
		if err != nil {
			return nil, err
		}
		storeType := types.ParseStoreType(backendName)
		return newBackendPIVKeyGenerator(b, storeType), nil
	}
	return SetPIVBackendResolver(resolver)
}
