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
	"crypto/x509"

	rootTruststore "github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

// LoadEmbeddedRoots returns compiled-in root certificates for the given
// certificate purpose. It bridges the root module's embedded PEM data
// into the xkey attestation verifier's EmbeddedRootsLoader function type.
//
// Currently supported purposes:
//   - PurposeAndroidHardware: returns Google Hardware Attestation Root CAs
//
// Returns nil for unsupported purposes.
func LoadEmbeddedRoots(purpose CertPurpose) []*x509.Certificate {
	loader, ok := embeddedLoaders[purpose]
	if !ok {
		return nil
	}
	return loader()
}

// embeddedLoaders maps certificate purposes to functions that return
// the corresponding embedded root certificates.
var embeddedLoaders = map[CertPurpose]func() []*x509.Certificate{
	PurposeAndroidHardware: loadGoogleHardwareAttestationRoots,
}

// loadGoogleHardwareAttestationRoots parses and returns the embedded Google
// Hardware Attestation Root CAs from the root truststore package.
func loadGoogleHardwareAttestationRoots() []*x509.Certificate {
	certs, err := rootTruststore.GoogleHardwareAttestationRoots()
	if err != nil {
		return nil
	}
	return certs
}
