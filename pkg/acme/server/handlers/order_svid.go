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

package handlers

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// orderProfiles lists the certificate profiles a newOrder may name, with
// the description the directory publishes in meta.profiles
// (draft-aaron-acme-profiles). An order that names no profile is issued as
// before.
var orderProfiles = map[string]string{
	ca.ProfileNameX509SVID: "X.509-SVID for a tenant service: one spiffe identifier, spiffe://<tenant>/svc/<name>, ordered by an account bound to that tenant",
}

var (
	// ErrSVIDIdentifierRequired is returned when an x509-svid order does not
	// name exactly one spiffe identifier.
	ErrSVIDIdentifierRequired = errors.New("handlers: an x509-svid order names exactly one spiffe identifier")

	// ErrSVIDIdentifierInvalid is returned when an x509-svid order's
	// identifier is not a canonical spiffe://<tenant>/<kind>/<name>.
	ErrSVIDIdentifierInvalid = errors.New("handlers: spiffe identifier is not spiffe://<tenant>/<kind>/<name>")

	// ErrSVIDKindNotService is returned when an x509-svid order names a
	// SPIFFE ID whose kind is not svc.
	ErrSVIDKindNotService = errors.New("handlers: an x509-svid order names a service, spiffe://<tenant>/svc/<name>")

	// ErrSVIDAccountNotTenantBound is returned when an account that is not
	// bound to a tenant orders an x509-svid.
	ErrSVIDAccountNotTenantBound = errors.New("handlers: x509-svid requires an account bound to a tenant")

	// ErrSVIDOtherTenant is returned when an account orders a SPIFFE ID in a
	// tenant other than the one it is bound to.
	ErrSVIDOtherTenant = errors.New("handlers: the spiffe identifier is outside the account's tenant")

	// ErrSVIDTenantCARequired is returned when the account's tenant has no
	// signing CA of its own: an SVID is never signed by the global CA, so
	// that each tenant's trust bundle is its own CA.
	ErrSVIDTenantCARequired = errors.New("handlers: x509-svid requires a tenant with its own signing CA")
)

// svidIdentity reads the SPIFFE ID an x509-svid order names and checks that
// the account may order it: the account is bound to a tenant, and the ID is
// a service in that tenant.
func svidIdentity(account *entities.ACMEAccount, identifiers []entities.ACMEIdentifier) (spiffe.ID, error) {
	if account.TenantID == "" {
		return spiffe.ID{}, ErrSVIDAccountNotTenantBound
	}
	if len(identifiers) != 1 || identifiers[0].Type != common.AuthzTypeSPIFFE {
		return spiffe.ID{}, ErrSVIDIdentifierRequired
	}

	value := identifiers[0].Value
	u, err := url.Parse(value)
	if err != nil {
		return spiffe.ID{}, &errs.Joined{Lead: ErrSVIDIdentifierInvalid, Cause: err}
	}
	id, ok, err := spiffe.ParseID(u)
	if err != nil {
		return spiffe.ID{}, &errs.Joined{Lead: ErrSVIDIdentifierInvalid, Cause: err}
	}
	if !ok {
		return spiffe.ID{}, ErrSVIDIdentifierInvalid
	}
	// The identifier is the certificate's URI SAN, so it must be exactly the
	// canonical form: no port, user info, query, fragment or escaping.
	canonical, err := id.URI()
	if err != nil {
		return spiffe.ID{}, &errs.Joined{Lead: ErrSVIDIdentifierInvalid, Cause: err}
	}
	if canonical.String() != value {
		return spiffe.ID{}, ErrSVIDIdentifierInvalid
	}

	if id.Kind != spiffe.KindService {
		return spiffe.ID{}, ErrSVIDKindNotService
	}
	if id.TenantID != account.TenantID {
		return spiffe.ID{}, ErrSVIDOtherTenant
	}
	return id, nil
}

// authorizeSVIDOrder checks an x509-svid newOrder: the identifier is a
// service in the account's own tenant, and that tenant signs with its own
// CA.
func (s *RestService) authorizeSVIDOrder(ctx context.Context, account *entities.ACMEAccount, identifiers []entities.ACMEIdentifier) error {
	if _, err := svidIdentity(account, identifiers); err != nil {
		return err
	}
	info, err := s.resolveTenantSigningCA(ctx, account, entities.CAPurposeGeneral)
	if err != nil {
		return err
	}
	if info == nil || info.UseGlobalDefault || info.Type == entities.SigningCATypeGlobal {
		return ErrSVIDTenantCARequired
	}
	return nil
}

// svidOrderProblem maps an x509-svid refusal to its ACME problem. Tenant CA
// resolution failures keep the problem tenantSigningCAProblem gives them.
func svidOrderProblem(err error) *entities.Error {
	switch {
	case errors.Is(err, ErrSVIDIdentifierRequired), errors.Is(err, ErrSVIDIdentifierInvalid):
		return common.MalformedError(err.Error(), nil)
	case errors.Is(err, ErrSVIDKindNotService):
		return common.RejectedIdentifier(err.Error())
	case errors.Is(err, ErrSVIDAccountNotTenantBound),
		errors.Is(err, ErrSVIDOtherTenant),
		errors.Is(err, ErrSVIDTenantCARequired):
		return common.Unauthorized(err.Error())
	default:
		return tenantSigningCAProblem(err)
	}
}

// saveSVIDAuthorization saves the authorization for an x509-svid order's
// identifier. It is valid from the start, with no challenges (RFC 8555
// Section 7.1.4): the account's tenant binding is what authorizes a name in
// that tenant, and authorizeSVIDOrder has already checked it.
func (s *RestService) saveSVIDAuthorization(ctx context.Context, dao qrdbsdk.GenericDAO[*entities.ACMEAuthorization], accountID, orderID uint64, identifier entities.ACMEIdentifier) (string, error) {
	authzID, err := GenerateID()
	if err != nil {
		return "", err
	}
	authzURL := fmt.Sprintf("%s/acme/authz/%d", s.baseRESTURI, authzID)
	authorization := &entities.ACMEAuthorization{
		ID:         authzID,
		OrderID:    orderID,
		AccountID:  accountID,
		Status:     common.StatusValid,
		Expires:    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		Identifier: identifier,
		Challenges: []entities.ACMEChallenge{},
		URL:        authzURL,
	}
	if err := dao.Save(ctx, authorization); err != nil {
		return "", err
	}
	return authzURL, nil
}

// matchesSVIDIdentifier checks an x509-svid CSR against the order's SPIFFE
// ID. The CA stamps the URI SAN and OU[0] itself, so the CSR may repeat
// them, and the service name as its CommonName, but may ask for no other
// name.
func matchesSVIDIdentifier(csr *x509.CertificateRequest, id spiffe.ID, uri string) *entities.Error {
	if len(csr.DNSNames) > 0 || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 {
		return common.BadCSR("x509-svid CSR must not contain DNS, IP or email names")
	}
	if len(csr.URIs) > 1 || (len(csr.URIs) == 1 && csr.URIs[0].String() != uri) {
		return common.BadCSR("x509-svid CSR may carry only the order's SPIFFE ID " + uri)
	}
	if cn := csr.Subject.CommonName; cn != "" && cn != id.Name {
		return common.BadCSR("x509-svid CSR CommonName must be empty or the service name " + id.Name)
	}
	if ou := csr.Subject.OrganizationalUnit; len(ou) > 1 || (len(ou) == 1 && ou[0] != id.TenantID) {
		return common.BadCSR("x509-svid CSR OrganizationalUnit must be empty or the tenant " + id.TenantID)
	}
	return nil
}

// svidFinalizeIdentity re-checks an x509-svid order at finalization, against
// the account's tenant binding as it stands now, and checks its CSR.
func svidFinalizeIdentity(account *entities.ACMEAccount, order *entities.ACMEOrder, csr *x509.CertificateRequest) (spiffe.ID, *entities.Error) {
	id, err := svidIdentity(account, order.Identifiers)
	if err != nil {
		return spiffe.ID{}, svidOrderProblem(err)
	}
	if problem := matchesSVIDIdentifier(csr, id, order.Identifiers[0].Value); problem != nil {
		return spiffe.ID{}, problem
	}
	return id, nil
}
