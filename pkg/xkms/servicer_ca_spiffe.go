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
	"context"
	"errors"
	"strconv"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// SPIFFE kind refusals for CSR signing (go-xkms#1659). Each is returned
// wrapped in an *ErrValidation, except ErrSPIFFEKindForbidden, which a
// *SPIFFEKindPermissionError carries.
var (
	// ErrSPIFFEKindUnknown is a SPIFFE kind other than user or svc.
	ErrSPIFFEKindUnknown = errors.New("ca: spiffe kind must be user or svc")

	// ErrSPIFFEKindWithoutTenant is a SPIFFE kind on a request that names no
	// tenant: the tenant is the SPIFFE URI's trust domain.
	ErrSPIFFEKindWithoutTenant = errors.New("ca: spiffe kind requires a tenant")

	// ErrSPIFFEKindWithoutTrustDomain is a SPIFFE kind on a node with no
	// cluster trust domain configured, which issues no SPIFFE URI SAN.
	ErrSPIFFEKindWithoutTrustDomain = errors.New("ca: spiffe kind requires a configured trust domain")

	// ErrSPIFFENameInvalid is a CSR CommonName that is not a SPIFFE path
	// segment ([A-Za-z0-9._-], not "." or "..").
	ErrSPIFFENameInvalid = errors.New("ca: csr common name is not a valid spiffe name")

	// ErrCSRMalformed is a CSR that is not a well-formed PKCS#10 request.
	ErrCSRMalformed = errors.New("ca: csr is not a well-formed pkcs#10 request")

	// ErrSPIFFEKindForbidden is a SPIFFE kind the caller holds no permission
	// to issue.
	ErrSPIFFEKindForbidden = errors.New("ca: caller may not issue this spiffe kind")
)

// SPIFFEKindPermissionError refuses a CSR whose SPIFFE kind needs a
// permission the caller does not hold. It matches ErrSPIFFEKindForbidden and
// the authorizer's own refusal under errors.Is.
type SPIFFEKindPermissionError struct {
	// Kind is the SPIFFE kind the request asked for.
	Kind string
	// Permission is the resource:action the kind requires.
	Permission string
	// Err is the authorizer's refusal.
	Err error
}

// Error reports the kind, the permission it needs and the refusal.
func (e *SPIFFEKindPermissionError) Error() string {
	return "ca: spiffe kind " + strconv.Quote(e.Kind) + " requires " + e.Permission + ": " + e.Err.Error()
}

// Unwrap returns ErrSPIFFEKindForbidden and the authorizer's refusal.
func (e *SPIFFEKindPermissionError) Unwrap() []error {
	return []error{ErrSPIFFEKindForbidden, e.Err}
}

// checkSPIFFEKind validates the SPIFFE kind a CSR signing request asks for.
// An empty kind needs nothing: the CA keeps its default. A kind needs a
// tenant, a configured trust domain and a CSR CommonName that is a valid
// SPIFFE name, since the issued URI is spiffe://<tenant>/<kind>/<CommonName>.
// A service identity (svc) is a credential no plain certs:issue caller may
// mint, so it also needs certs:issue_service, checked below the transport
// gate the same way ssh:service is.
func (s *XKMSService) checkSPIFFEKind(ctx context.Context, req *transport.SignCSRRequest) error {
	switch req.SPIFFEKind {
	case "":
		return nil
	case spiffe.KindUser, spiffe.KindService:
	default:
		return &ErrValidation{Sentinel: ErrSPIFFEKindUnknown, Detail: strconv.Quote(req.SPIFFEKind)}
	}
	if req.TenantID == "" {
		return &ErrValidation{Sentinel: ErrSPIFFEKindWithoutTenant}
	}
	if s.SPIFFETrustDomain() == "" {
		return &ErrValidation{Sentinel: ErrSPIFFEKindWithoutTrustDomain}
	}
	if req.SPIFFEKind == spiffe.KindService {
		if err := s.AuthorizeCaller(ctx, auth.ResourceCerts, auth.ActionIssueService); err != nil {
			return &SPIFFEKindPermissionError{
				Kind:       req.SPIFFEKind,
				Permission: auth.ResourceCerts + ":" + auth.ActionIssueService,
				Err:        err,
			}
		}
	}
	csr, err := parseCSRAny(req.CSRPEM)
	if err != nil {
		return &ErrValidation{Sentinel: ErrCSRMalformed, Detail: err.Error()}
	}
	if err := spiffe.ValidateName(csr.Subject.CommonName); err != nil {
		return &ErrValidation{Sentinel: ErrSPIFFENameInvalid, Detail: err.Error()}
	}
	return nil
}
