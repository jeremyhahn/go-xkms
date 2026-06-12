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

package hardware

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
)

// PutIfAbsent stores certificate data for key only when no certificate already
// exists for that id, mirroring Put's certs/* key mapping. The existence check
// and the write are performed under the adapter's write lock, so the
// check-then-write is atomic for this process (the hardware token is the single
// writer). Returns stored=false when a certificate already exists.
func (a *HardwareBackendAdapter) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !strings.HasPrefix(key, "certs/") {
		return false, fmt.Errorf("hardware storage only supports certificate keys (certs/*): got %s", key)
	}

	// Certificate chain.
	if strings.HasSuffix(key, "-chain.pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, "-chain.pem")

		exists, err := a.hardware.CertExists(id)
		if err != nil {
			return false, err
		}
		if exists {
			return false, nil
		}

		chain, err := parseDERChain(value)
		if err != nil {
			return false, fmt.Errorf("failed to parse certificate chain: %w", err)
		}
		if err := a.hardware.SaveCertChain(id, chain); err != nil {
			return false, err
		}
		return true, nil
	}

	// Single certificate.
	if strings.HasSuffix(key, ".pem") {
		id := strings.TrimPrefix(key, "certs/")
		id = strings.TrimSuffix(id, ".pem")

		exists, err := a.hardware.CertExists(id)
		if err != nil {
			return false, err
		}
		if exists {
			return false, nil
		}

		cert, err := x509.ParseCertificate(value)
		if err != nil {
			return false, fmt.Errorf("failed to parse certificate: %w", err)
		}
		if err := a.hardware.SaveCert(id, cert); err != nil {
			return false, err
		}
		return true, nil
	}

	return false, fmt.Errorf("unsupported key format: %s", key)
}
