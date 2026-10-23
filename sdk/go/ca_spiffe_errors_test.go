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

package xkms

import (
	"errors"
	"testing"

	pkgxkms "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// errDenied stands in for the authorizer's refusal.
var errDenied = errors.New("denied")

// TestServiceSPIFFEKindPermissionError_MatchesForbidden proves an embedded
// caller can tell a refused svc request apart through the SDK alone
// (go-xkms#1659).
func TestServiceSPIFFEKindPermissionError_MatchesForbidden(t *testing.T) {
	var err error = &pkgxkms.SPIFFEKindPermissionError{Kind: "svc", Permission: "certs:issue_service", Err: errDenied}

	if !errors.Is(err, ServiceErrSPIFFEKindForbidden) {
		t.Fatalf("errors.Is(%v, ServiceErrSPIFFEKindForbidden) = false, want true", err)
	}
	var refusal *ServiceSPIFFEKindPermissionError
	if !errors.As(err, &refusal) || refusal.Permission != "certs:issue_service" {
		t.Fatalf("errors.As(%v) did not yield the permission refusal", err)
	}
}

// TestServiceSPIFFEKindValidationErrors_MatchService proves each validation
// sentinel the SDK names is the one the service returns, and that they stay
// distinct from the permission refusal.
func TestServiceSPIFFEKindValidationErrors_MatchService(t *testing.T) {
	tests := []struct {
		name string
		sdk  error
		pkg  error
	}{
		{"unknown kind", ServiceErrSPIFFEKindUnknown, pkgxkms.ErrSPIFFEKindUnknown},
		{"without tenant", ServiceErrSPIFFEKindWithoutTenant, pkgxkms.ErrSPIFFEKindWithoutTenant},
		{"without trust domain", ServiceErrSPIFFEKindWithoutTrustDomain, pkgxkms.ErrSPIFFEKindWithoutTrustDomain},
		{"invalid name", ServiceErrSPIFFENameInvalid, pkgxkms.ErrSPIFFENameInvalid},
		{"malformed csr", ServiceErrCSRMalformed, pkgxkms.ErrCSRMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &pkgxkms.ErrValidation{Sentinel: tt.pkg}
			if !errors.Is(err, tt.sdk) {
				t.Fatalf("errors.Is(%v, %v) = false, want true", err, tt.sdk)
			}
			if errors.Is(err, ServiceErrSPIFFEKindForbidden) {
				t.Fatalf("validation error %v matched ServiceErrSPIFFEKindForbidden", err)
			}
		})
	}
}
