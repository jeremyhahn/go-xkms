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
	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/acme/policy"
)

// validateIdentifierFormat performs RFC 1035 (DNS), RFC 8738 (IP), or
// minimal (permanent-identifier) syntax validation on an identifier,
// independent of server policy. A non-nil error is always reported to the
// client as RFC 8555 "malformed": the request itself is not well-formed,
// regardless of what the server's issuance policy allows.
//
// Public-suffix enforcement is deliberately excluded here even for DNS
// identifiers: whether "internal" or "localhost"-style names are accepted
// is a policy decision (see checkIdentifierPolicy), not a syntax error.
func validateIdentifierFormat(id entities.ACMEIdentifier) error {
	switch id.Type {
	case common.AuthzTypeDNS:
		v := &policy.DomainValidator{RequirePublicSuffix: false, AllowWildcards: true}
		return v.ValidateDomain(id.Value)
	case common.AuthzTypeIP:
		return policy.ValidateIP(id.Value)
	case common.AuthzTypePermanentIdentifier:
		return policy.ValidateIdentifier(policy.IdentifierTypePermanentIdentifier, id.Value)
	default:
		return policy.NewPolicyError(policy.ErrUnsupportedIdentifierType, id.Type, id.Value, "")
	}
}

// checkIdentifierPolicy applies the server's issuance policy to a
// syntactically valid identifier: the domain/FQDN/wildcard/CIDR blocklist,
// public-suffix enforcement, and reserved-IP rejection. A non-nil error is
// always reported to the client as RFC 8555 "rejectedIdentifier": the
// identifier is well-formed but the server refuses to issue for it.
//
// Callers must run validateIdentifierFormat first; the public-suffix and
// reserved-IP checks below assume the identifier already passed syntax
// validation, so any error they return is specifically a policy refusal.
// Permanent identifiers are TPM/TCG key material or device serials, not
// names, so no blocklist or format policy applies to them.
func (s *RestService) checkIdentifierPolicy(id entities.ACMEIdentifier) error {
	switch id.Type {
	case common.AuthzTypeDNS, common.AuthzTypeIP:
		if err := s.blocklist.CheckIdentifier(id.Type, id.Value); err != nil {
			return err
		}
	}

	switch id.Type {
	case common.AuthzTypeDNS:
		if s.requirePublicSuffix {
			v := &policy.DomainValidator{RequirePublicSuffix: true, AllowWildcards: true}
			if err := v.ValidateDomain(id.Value); err != nil {
				return err
			}
		}
	case common.AuthzTypeIP:
		if s.rejectReservedIPs {
			if err := policy.ValidateIPWithReservedCheck(id.Value); err != nil {
				return err
			}
		}
	}

	return nil
}
