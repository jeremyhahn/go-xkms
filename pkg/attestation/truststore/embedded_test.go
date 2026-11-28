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

package truststore

import (
	"testing"
)

func TestLoadEmbeddedRoots_AndroidHardware(t *testing.T) {
	certs := LoadEmbeddedRoots(PurposeAndroidHardware)
	if len(certs) == 0 {
		t.Fatal("LoadEmbeddedRoots(PurposeAndroidHardware) returned no certificates")
	}
	// Google embeds 3 hardware attestation root CAs (2x RSA + 1x EC)
	if len(certs) < 3 {
		t.Errorf("LoadEmbeddedRoots(PurposeAndroidHardware) returned %d certificates, expected at least 3", len(certs))
	}
	for i, cert := range certs {
		if cert == nil {
			t.Errorf("certificate at index %d is nil", i)
			continue
		}
		if !cert.IsCA {
			t.Errorf("certificate at index %d (%s) is not a CA", i, cert.Subject.CommonName)
		}
	}
}

func TestLoadEmbeddedRoots_UnsupportedPurpose(t *testing.T) {
	unsupported := []CertPurpose{
		PurposeGeneral,
		PurposeTPMManufacturer,
		PurposeIDevIDIssuer,
		PurposeUserCA,
		PurposeBootstrapCA,
		PurposeImageSigner,
		CertPurpose("nonexistent"),
	}
	for _, purpose := range unsupported {
		certs := LoadEmbeddedRoots(purpose)
		if certs != nil {
			t.Errorf("LoadEmbeddedRoots(%q) returned %d certificates, expected nil", purpose, len(certs))
		}
	}
}
