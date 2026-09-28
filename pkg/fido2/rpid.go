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

package fido2

import (
	"net"
	"net/url"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"golang.org/x/net/publicsuffix"
)

// ValidateRPID enforces the WebAuthn client-side binding between a relying
// party ID and the caller's origin (WebAuthn L2 §5.1.3 step 8 and §5.1.4.1
// step 7): rpID must equal the origin's effective domain, or be a registrable
// domain suffix of it. A suffix that is itself a public suffix ("com",
// "co.uk", "github.io") is refused, as is any suffix of an IP-address origin.
//
// The rpID arrives in server-supplied ceremony options, so this is what stops
// a relying party from asking the authenticator to exercise a credential
// scoped to a domain it does not control. The origin is the caller's own
// security context and is never derived from the rpID: an empty origin is
// refused with ErrOriginRequired.
func ValidateRPID(rpID, origin string) error {
	if origin == "" {
		return ErrOriginRequired
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return &errs.Joined{Lead: ErrInvalidOrigin, Cause: err}
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Scheme == "" || host == "" {
		return &errs.Detail{Err: ErrInvalidOrigin, Detail: origin}
	}

	rp := strings.ToLower(rpID)
	if rp == host {
		return nil
	}
	if !isRegistrableSuffix(rp, host) {
		return &errs.Detail{Err: ErrRPIDOriginMismatch, Detail: "rpId " + rpID + " for origin " + origin}
	}
	return nil
}

// isRegistrableSuffix reports whether rp is a proper registrable-domain
// suffix of host: host ends in "."+rp, host is a domain name rather than an
// IP address, and rp is not itself a public suffix.
func isRegistrableSuffix(rp, host string) bool {
	if rp == "" || net.ParseIP(host) != nil {
		return false
	}
	if !strings.HasSuffix(host, "."+rp) {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(rp)
	return suffix != rp
}
