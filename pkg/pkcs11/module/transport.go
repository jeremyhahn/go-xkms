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

// Package module provides the core PKCS#11 (Cryptoki) v3.0 module implementation.
//
// This file defines the PKCS11Transport interface — the minimal set of transport
// methods that the PKCS#11 module actually calls. The module handles sessions,
// slots, tokens, objects, mechanisms, digesting, multi-part operations, and random
// generation internally without transport calls. Only 20 methods are needed for
// backend delegation.
//
// All existing transports (gRPC, REST, Unix, embedded) satisfy this interface
// automatically via Go structural typing since they implement the full
// transport.Client which is a superset.
//
// References:
//   - OASIS PKCS#11 v3.0: https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html
package module

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// PKCS11Transport defines the minimal transport interface required by the PKCS#11
// module. This is a consumer-side interface containing only the 20 methods the
// module actually calls, rather than the full 116-method transport.Client.
//
// The module handles sessions, slots, tokens, objects, mechanisms, digesting,
// multi-part operations, and random generation internally. Only backend-delegated
// operations (key generation, signing, verification, encryption, decryption,
// key derivation, key wrapping, key export, and PIV) require transport calls.
//
// All existing transport implementations (gRPC, REST, Unix, embedded) satisfy
// this interface automatically via Go structural typing.
type PKCS11Transport interface {
	// Connect establishes a connection to the backend.
	Connect(ctx context.Context) error

	// Close closes the connection to the backend.
	Close() error

	// GenerateKey generates a cryptographic key in the backend.
	GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error)

	// Sign signs data with the specified key.
	Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error)

	// Verify verifies a signature.
	Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error)

	// Encrypt encrypts data with the specified key.
	Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error)

	// Decrypt decrypts data with the specified key.
	Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error)

	// DeriveKey derives a key using the specified algorithm and parameters.
	DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error)

	// DeriveKeyECDH performs ECDH key agreement and derives a symmetric key.
	DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error)

	// WrapKeyByID wraps a target key using a wrapping key, both identified by key IDs.
	WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error)

	// UnwrapKeyByID unwraps key material and imports it as a new key.
	UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error)

	// ExportKeyMaterial exports raw symmetric key bytes for extractable keys.
	ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error)

	// ListPIVSlots returns the status of all PIV slots in the specified backend.
	ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error)

	// GetPIVCertificate retrieves the certificate from a PIV slot.
	GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error)

	// GeneratePIVKey generates a new key pair in a PIV slot.
	GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error)

	// StorePIVCertificate stores a certificate in a PIV slot.
	StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error

	// DeletePIVCertificate removes the certificate from a PIV slot.
	DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error

	// ImportPIVCertificate imports an externally issued certificate into a PIV slot.
	ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error

	// ExportPIVCertificate exports the certificate from a PIV slot in the requested format.
	ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error)

	// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
	GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error)
}

// Compile-time check: transport.Client satisfies PKCS11Transport.
// This proves all existing transports (gRPC, REST, Unix, embedded) auto-satisfy
// PKCS11Transport via Go structural typing.
var _ PKCS11Transport = (transport.Client)(nil)
