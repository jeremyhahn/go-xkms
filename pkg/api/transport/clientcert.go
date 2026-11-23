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

import "crypto/tls"

// PresentClientCertificate makes cfg offer cert on every client
// certificate request, whatever acceptable CAs the server names.
//
// Go's TLS client only sends a certificate from tls.Config.Certificates when
// the server's certificate request names its issuer; otherwise it silently
// sends none and the server reports "no client certificate provided". The
// configured certificate is the caller's identity, so it is always offered
// and the server decides whether to accept it. Certificates keeps the pair
// for callers that inspect it; GetClientCertificate takes precedence.
func PresentClientCertificate(cfg *tls.Config, cert tls.Certificate) {
	cfg.Certificates = []tls.Certificate{cert}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &cert, nil
	}
}
