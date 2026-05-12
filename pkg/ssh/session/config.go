// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package session

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// defaultTimeout is the fallback per-operation deadline used when a
// DialRequest omits Timeout. Matches the legacy client value.
const defaultTimeout = 10 * time.Second

// defaultPort is the fallback TCP port. SSH convention.
const defaultPort = 22

// buildClientConfig constructs the ssh.ClientConfig. It is pulled into
// its own function so Dial remains a linear orchestration and so tests
// can cover configuration independently.
//
// Sensible defaults:
//   - Timeout: caller-provided or defaultTimeout
//   - BannerCallback: discarded (we don't surface pre-auth banners)
//
// No custom KEX / cipher / MAC pinning: we defer to x/crypto/ssh's
// current default list, which tracks modern OpenSSH behaviour and is
// updated by the Go team. Overriding here would be a maintenance
// burden without a concrete threat model that justifies it.
func buildClientConfig(req DialRequest, signer ssh.Signer, hostCallback ssh.HostKeyCallback) *ssh.ClientConfig {
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &ssh.ClientConfig{
		User:            req.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostCallback,
		Timeout:         timeout,
	}
}
