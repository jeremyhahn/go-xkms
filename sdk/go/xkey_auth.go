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

package xkms

import (
	"crypto/tls"

	"github.com/jeremyhahn/go-xkms/pkg/xkeysigner"
)

// xkeyAuthResolver resolves authentication configuration from the xkey daemon
// via IPC. It probes for a PIV 9a certificate to determine whether mTLS
// authentication is available.
type xkeyAuthResolver struct {
	socketPath string
}

// ResolveTLSConfig creates a *tls.Config using the xkey IPC signer for mTLS
// client certificate authentication. The PIV slot 9a certificate and signing
// key are accessed through the running xkey daemon.
func (r *xkeyAuthResolver) ResolveTLSConfig() (*tls.Config, error) {
	return xkeysigner.TLSClientConfig(&xkeysigner.TLSConfig{
		SignerConfig: &xkeysigner.SignerConfig{
			SocketPath: r.socketPath,
			Slot:       "9a",
		},
	})
}

// HasCertificate probes the xkey daemon to check whether a PIV 9a certificate
// is available. It returns true if a certificate was found, false otherwise.
func (r *xkeyAuthResolver) HasCertificate() bool {
	signer, err := xkeysigner.NewSigner(&xkeysigner.SignerConfig{
		SocketPath: r.socketPath,
		Slot:       "9a",
	})
	if err != nil {
		return false
	}
	defer signer.Close()
	return signer.Public() != nil
}
