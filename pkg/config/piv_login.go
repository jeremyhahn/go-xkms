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

package config

import "crypto/x509"

// LoadPIVAttestationPools reads the attestation anchors the PIV login
// exchange verifies against. roots is nil when no bundle is configured, which
// the exchange treats as "no anchor" and refuses unless AllowUnattested is
// set; intermediates is nil when none are listed. A bundle that cannot be
// read or holds no certificate is an error, never an empty pool: an anchor
// the operator named but that loads as nothing would turn every login into a
// refusal that looks like a bad card.
func LoadPIVAttestationPools(cfg *PIVLoginConfig) (roots, intermediates *x509.CertPool, err error) {
	if cfg == nil || cfg.AttestationRoots == "" {
		return nil, nil, nil
	}
	roots, err = loadCertPool(cfg.AttestationRoots, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(cfg.AttestationIntermediates) == 0 {
		return roots, nil, nil
	}
	intermediates, err = loadCertPool("", cfg.AttestationIntermediates)
	if err != nil {
		return nil, nil, err
	}
	return roots, intermediates, nil
}
