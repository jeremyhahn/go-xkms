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

package trustedca

import (
	http01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/http-01"
)

// =============================================================================
// Client-side http-01 Challenge Responder
// =============================================================================
//
// ACMEVerifyHTTP01 is the ACME *server* half of the http-01 challenge: the
// directory fetching the key authorization from the client under validation.
// The symbols below are the *client* half — the short-lived HTTP server an
// ACME client runs so that fetch succeeds.
//
// A consumer fills ACMECertificateRequest.ChallengeSetup with a call to
// NewHTTP01Responder and ACMECertificateRequest.ChallengeCleanup with the
// responder's Close:
//
//	var responder *trustedca.HTTP01Responder
//
//	req := trustedca.ACMECertificateRequest{
//		AuthzType:     trustedca.ACMEAuthzTypeDNS,
//		AuthzValue:    fqdn,
//		ChallengeType: trustedca.ACMEChallengeTypeHTTP01,
//		CSR:           csr,
//		ChallengeSetup: func(challengeType, token, keyAuth string) error {
//			r, err := trustedca.NewHTTP01Responder(trustedca.HTTP01ResponderConfig{
//				Addr:    "80",
//				KeyAuth: keyAuth,
//			})
//			if err != nil {
//				return err
//			}
//			responder = r
//			return nil
//		},
//		ChallengeCleanup: func(challengeType string) {
//			if responder != nil {
//				_ = responder.Close()
//			}
//		},
//	}
//
// The bind happens inside NewHTTP01Responder, so ChallengeSetup returning nil
// means the responder is already answering requests and the order may be
// accepted immediately. A caller that cannot take the address — no
// CAP_NET_BIND_SERVICE for port 80, or a port already held — gets an
// HTTP01ResponderBindError from ChallengeSetup instead of an opaque
// authorization failure several round trips later.
//
// Each responder owns its own listener, so several orders may be in flight at
// once as long as they are given different addresses.

// HTTP01Responder serves the key authorization for one http-01 challenge. It
// is bound and serving from the moment NewHTTP01Responder returns until
// Shutdown or Close is called, and all of its methods are safe for concurrent
// use.
type HTTP01Responder = http01.Responder

// HTTP01ResponderConfig configures an HTTP01Responder. Addr and KeyAuth are
// required; every other field falls back to the corresponding
// DefaultHTTP01Responder constant.
type HTTP01ResponderConfig = http01.ResponderConfig

// HTTP01ResponderConfigError reports an HTTP01ResponderConfig field that
// cannot be used.
type HTTP01ResponderConfigError = http01.ResponderConfigError

// HTTP01ResponderBindError reports that the responder could not take the
// address it was asked to listen on. It unwraps to the underlying net error.
type HTTP01ResponderBindError = http01.ResponderBindError

// HTTP01ResponderShutdownError reports that a graceful shutdown did not
// complete before its deadline. It unwraps to the underlying cause.
type HTTP01ResponderShutdownError = http01.ResponderShutdownError

// NewHTTP01Responder binds a listener and starts serving the key
// authorization at the well-known http-01 challenge path.
//
// A non-nil error means nothing is listening and the ACME server must not be
// notified; a nil error means the responder is already accepting connections.
// The caller owns the responder and must release it with Shutdown or Close.
var NewHTTP01Responder = http01.NewResponder

const (
	// DefaultHTTP01ResponderShutdownTimeout bounds a graceful shutdown when
	// the caller's context carries no deadline of its own.
	DefaultHTTP01ResponderShutdownTimeout = http01.DefaultShutdownTimeout

	// DefaultHTTP01ResponderReadTimeout is the per-request header and body
	// read budget.
	DefaultHTTP01ResponderReadTimeout = http01.DefaultReadTimeout

	// DefaultHTTP01ResponderWriteTimeout is the per-request response write
	// budget.
	DefaultHTTP01ResponderWriteTimeout = http01.DefaultWriteTimeout

	// DefaultHTTP01ResponderIdleTimeout is how long a keep-alive connection
	// may sit unused.
	DefaultHTTP01ResponderIdleTimeout = http01.DefaultIdleTimeout
)
