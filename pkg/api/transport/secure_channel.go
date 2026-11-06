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

package transport

import (
	"os"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// EnvAllowInsecureTransport is the environment variable that sets
// Config.AllowInsecureTransport. When it is set, it overrides the field; a
// value strconv.ParseBool rejects keeps the guard on. Loopback tests and dev
// setups only, never production.
const EnvAllowInsecureTransport = "XKMS_TRANSPORT_ALLOW_INSECURE_TRANSPORT"

// IsUnixEndpoint reports whether address names a unix domain socket
// ("unix:path" or "unix:///path"), the one endpoint a client may reach with
// TLS disabled (ruling 152).
func IsUnixEndpoint(address string) bool {
	return strings.HasPrefix(address, "unix:")
}

// RequireSecureChannel refuses a plaintext channel to a non-unix endpoint
// before any request leaves the process (ruling 152). The caller decides
// whether its channel is plaintext, because that reading differs per
// transport (gRPC: TLSEnabled and the dial target; REST: the URL scheme);
// name identifies the transport in the error. It returns nil for an
// encrypted channel or when the AllowInsecureTransport opt-out is set.
func (c *Config) RequireSecureChannel(name string, plaintext bool) error {
	if !plaintext || c.insecureTransportAllowed() {
		return nil
	}
	return &errs.Detail{Err: ErrInsecureTransport, Detail: name}
}

// insecureTransportAllowed reports the opt-out: the environment variable
// when set, the config field otherwise.
func (c *Config) insecureTransportAllowed() bool {
	value := os.Getenv(EnvAllowInsecureTransport)
	if value == "" {
		return c.AllowInsecureTransport
	}
	allowed, err := strconv.ParseBool(value)
	if err != nil {
		// An unreadable opt-out is not an opt-out: keep the guard on.
		return false
	}
	return allowed
}
