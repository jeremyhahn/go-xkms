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
	"encoding/pem"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// The PIV methods operate the server's own PIV card, platform-global
// hardware, so each is platform-scoped (requirePlatformScope, go-xkms#1227): a
// tenant-scoped caller is refused with a *TenantBindingError that reads as
// not-found, before the card is touched.

// ListPIVSlots returns the status of all PIV slots for the specified backend.
// Implements the PIVServicer interface.
func (s *XKMSService) ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if err := requirePlatformScope(ctx, "list PIV slots", ""); err != nil {
		return nil, err
	}
	return ListPIVSlots(ctx, req)
}

// GetPIVCertificate retrieves a certificate from a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if err := requirePlatformScope(ctx, "get PIV certificate", ""); err != nil {
		return nil, err
	}
	return GetPIVCertificate(ctx, req)
}

// StorePIVCertificate stores a certificate in a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if err := requirePlatformScope(ctx, "store PIV certificate", ""); err != nil {
		return err
	}
	return StorePIVCertificate(ctx, req)
}

// DeletePIVCertificate removes a certificate from a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	if err := requirePlatformScope(ctx, "delete PIV certificate", ""); err != nil {
		return err
	}
	return DeletePIVCertificate(ctx, req)
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
// Implements the PIVServicer interface.
func (s *XKMSService) GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	if err := requirePlatformScope(ctx, "generate PIV key", ""); err != nil {
		return nil, err
	}
	return GeneratePIVKey(ctx, req)
}

// ImportPIVCertificate imports a certificate into a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	if err := requirePlatformScope(ctx, "import PIV certificate", ""); err != nil {
		return err
	}
	return ImportPIVCertificate(ctx, req)
}

// ExportPIVCertificate exports a certificate from a PIV slot.
// Implements the PIVServicer interface.
func (s *XKMSService) ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if err := requirePlatformScope(ctx, "export PIV certificate", ""); err != nil {
		return nil, err
	}
	return ExportPIVCertificate(ctx, req)
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
// Implements the PIVServicer interface.
func (s *XKMSService) GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	if err := requirePlatformScope(ctx, "generate PIV CSR", ""); err != nil {
		return nil, err
	}
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
		// b.Type(), not ParseStoreType(backendName): a backend registered
		// under a name that is not a store-type keyword (e.g. "token-a")
		// must still report its real kind, not the "unknown"
		// ParseStoreType(backendName) would give it (go-xkms#312).
		return newBackendPIVKeyGenerator(b, b.Type()), nil
	}
	return SetPIVBackendResolver(resolver)
}

// InitPIVCASignFunc configures the PIV manager to sign CSRs using the
// CA provider registered with this XKMSService. This enables the "ca-signed"
// output format for PIV key generation.
func (s *XKMSService) InitPIVCASignFunc() error {
	ca, err := s.getCA()
	if err != nil {
		return nil // CA not configured — ca-signed mode will return ErrPIVCASignFuncNotSet
	}

	fn := func(ctx context.Context, csrPEM []byte, profile string, validityDays int) ([]byte, []byte, error) {
		cert, signErr := ca.SignCSRRaw(ctx, csrPEM, profile, validityDays)
		if signErr != nil {
			return nil, nil, signErr
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

		// Build CA chain PEM.
		var chainPEM []byte
		caCert, caErr := ca.CACertificate()
		if caErr == nil && caCert != nil {
			chainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
		}
		return certPEM, chainPEM, nil
	}
	return SetPIVCASignFunc(fn)
}
