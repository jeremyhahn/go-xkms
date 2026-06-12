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

package bootstrap

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/jeremyhahn/go-truststrap/pkg/dane"
	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

// ErrHostnameRequired is returned by NewDANETLSConfig when neither the
// DANEConfig nor the hostname parameter provides a hostname for the
// TLSA lookup.
var ErrHostnameRequired = errors.New("trust bootstrap: hostname required")

// NewDANETLSConfig returns a client *tls.Config whose sole certificate
// verification is DANE/TLSA validation of the presented chain per
// RFC 7671 (the documented custom-verifier pattern: WebPKI verification
// is disabled and a VerifyConnection callback is the only verifier).
//
// TLSA records are resolved eagerly for "_<port>._tcp.<hostname>." so
// callers can fall back to another trust strategy before dialing when
// no DANE-usable records exist. The hostname used for both the TLSA
// lookup and the chain verification is cfg.Hostname when set, otherwise
// the hostname parameter — the same precedence DANEBootstrapper applies.
//
// cfg supplies the resolver knobs (DNSServer, DNSOverTLS,
// DNSTLSServerName); a nil cfg or empty DNSServer uses the system
// resolver from /etc/resolv.conf with DNSSEC AD-flag enforcement.
// Because records are resolved at construction time, build a fresh
// config per connection attempt to honor DNS TTLs.
func NewDANETLSConfig(ctx context.Context, cfg *DANEConfig, hostname string, port uint16) (*tls.Config, error) {
	effective := hostname
	resolverCfg := &dane.ResolverConfig{RequireAD: true}
	if cfg != nil {
		if cfg.Hostname != "" {
			effective = cfg.Hostname
		}
		resolverCfg.Server = cfg.DNSServer
		resolverCfg.UseTLS = cfg.DNSOverTLS
		resolverCfg.TLSServerName = cfg.DNSTLSServerName
	}
	if effective == "" {
		return nil, ErrHostnameRequired
	}
	resolver, err := dane.NewResolver(resolverCfg)
	if err != nil {
		return nil, err
	}
	return dane.NewVerifiedTLSConfig(ctx, effective, port, resolver)
}

// NewSPKIPinTLSConfig returns a client *tls.Config whose sole
// certificate verification is a SHA-256 SubjectPublicKeyInfo pin match
// against the presented chain (the documented custom-verifier pattern).
// pin is the hex-encoded SHA-256 SPKI pin (64 hex characters), the same
// value carried by SPKIConfig.Pin.
func NewSPKIPinTLSConfig(pin string) (*tls.Config, error) {
	return spkipin.NewPinnedTLSConfig(pin)
}
