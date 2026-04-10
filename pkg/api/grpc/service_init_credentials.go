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

package grpc

import (
	"errors"

	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
)

// Typed errors for init ceremony and credential gRPC operations.
var (
	// ErrCeremonyServiceNotConfigured is returned when the ceremony service
	// has not been configured via SetCeremonyService.
	ErrCeremonyServiceNotConfigured = errors.New("grpc: ceremony service not configured")

	// ErrCredentialServiceNotConfigured is returned when the credential
	// service has not been configured via SetCredentialService.
	ErrCredentialServiceNotConfigured = errors.New("grpc: credential service not configured")
)

// Package-level service references for init ceremony and credential management.
// The ceremony service is stored as any to break the import cycle:
// grpc -> init -> ca -> xkms -> grpc. The concrete type is
// *initialize.CeremonyService; callers type-assert after retrieval.
var (
	ceremonyService   any
	credentialService *credentialspkg.Service
)

// SetCeremonyService configures the init ceremony service for the gRPC service.
// The value is stored as any to avoid an import cycle with pkg/init.
// The concrete type must be *initialize.CeremonyService.
// This must be called before any init ceremony RPCs can be used.
func SetCeremonyService(svc any) {
	ceremonyService = svc
}

// GetCeremonyService returns the configured ceremony service, or nil if not set.
// Callers must type-assert to *initialize.CeremonyService.
func GetCeremonyService() any {
	return ceremonyService
}

// SetCredentialService configures the credential management service for the gRPC service.
// This must be called before any credential RPCs can be used.
func SetCredentialService(svc *credentialspkg.Service) {
	credentialService = svc
}

// GetCredentialService returns the configured credential service, or nil if not set.
func GetCredentialService() *credentialspkg.Service {
	return credentialService
}
