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

package ca

import (
	"reflect"
	"testing"
)

// trustedCAMethods is the complete exported method set of TrustedCA, excluding
// Sign and Public, which are promoted from the embedded crypto.Signer.
//
// sdk/go/ca.go declares `type TrustedCA = pkgca.TrustedCA`, so this set is
// public SDK API: removing or renaming an entry breaks every downstream
// implementor and caller. TrustedCA is now composed from fifteen
// sub-interfaces, which makes that easy to do by accident -- dropping one from
// the composition compiles cleanly, still satisfies `var _ TrustedCA =
// (*CA)(nil)` (the concrete CA keeps every method either way), and silently
// shrinks the published interface. Nothing else in the build would notice.
//
// This table is written out rather than derived so it fails on exactly that.
// It is the same reasoning as the transport authorization golden tables: when
// a value IS the contract, the test has to state it independently.
var trustedCAMethods = map[string]struct{}{
	"Blob":                                   {},
	"CABundle":                               {},
	"CABundleCertPool":                       {},
	"CABundleFiltered":                       {},
	"CACertificate":                          {},
	"CAKeyAttributes":                        {},
	"CASigner":                               {},
	"CRL":                                    {},
	"Certificate":                            {},
	"CertificatePEM":                         {},
	"CertStore":                              {},
	"ClientTLSConfig":                        {},
	"Config":                                 {},
	"CreateCSR":                              {},
	"CrossSignedPEM":                         {},
	"DefaultKeyAlgorithm":                    {},
	"DefaultSignatureAlgorithm":              {},
	"DefaultValidityPeriod":                  {},
	"Exists":                                 {},
	"GenerateCRL":                            {},
	"Hash":                                   {},
	"Identity":                               {},
	"ImportAttestation":                      {},
	"ImportAttestationEventLog":              {},
	"ImportAttestationKeyCertificate":        {},
	"ImportAttestationPCRs":                  {},
	"ImportAttestationQuote":                 {},
	"ImportBlob":                             {},
	"ImportCertificate":                      {},
	"ImportCertificatePEM":                   {},
	"ImportDistributionCRLs":                 {},
	"ImportIssuingCAs":                       {},
	"ImportLocalAttestation":                 {},
	"ImportXSignedCertificate":               {},
	"Init":                                   {},
	"IsAutoImportingIssuerCAs":               {},
	"IsInitialized":                          {},
	"IsRevoked":                              {},
	"IssueCertificate":                       {},
	"IssueCertificateWithProfile":            {},
	"IssuingIdentity":                        {},
	"KeyStore":                               {},
	"Load":                                   {},
	"OSTrustStore":                           {},
	"ParseBundle":                            {},
	"PEM":                                    {},
	"PrivateKey":                             {},
	"PubKey":                                 {},
	"QuantumSafeTLSConfig":                   {},
	"Revoke":                                 {},
	"RevokeCert":                             {},
	"RootCertificate":                        {},
	"ServerTLSConfig":                        {},
	"SignCSR":                                {},
	"SignedBlob":                             {},
	"Signer":                                 {},
	"TLSBundle":                              {},
	"TLSBundleWithCrossSigner":               {},
	"TLSCertificate":                         {},
	"TLSConfig":                              {},
	"TLSConfigWithXSigner":                   {},
	"TrustedIntermediate":                    {},
	"TrustedIntermediateCertPool":            {},
	"TrustedIntermediateCertPoolWithXSigner": {},
	"TrustedRoot":                            {},
	"TrustedRootCertPool":                    {},
	"TrustedRootCertPoolWithXSigner":         {},
	"Verify":                                 {},
	"VerifyAttestationEventLog":              {},
	"VerifyAttestationPCRs":                  {},
	"VerifyAttestationQuote":                 {},
	"VerifyTCG_CSR_IDevIDBytes":              {},
	"XSignedCertificate":                     {},
	"XSignedIntermediateCertificates":        {},
	"XSignedRootCertificate":                 {},
}

// TestTrustedCA_MethodSetIsStable pins TrustedCA's composed method set in both
// directions, so neither a dropped sub-interface nor an unreviewed addition to
// the public interface can pass unnoticed.
func TestTrustedCA_MethodSetIsStable(t *testing.T) {
	iface := reflect.TypeOf((*TrustedCA)(nil)).Elem()

	got := make(map[string]struct{}, iface.NumMethod())
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		// Sign and Public come from the embedded crypto.Signer.
		if name == "Sign" || name == "Public" {
			continue
		}
		got[name] = struct{}{}
	}

	for name := range trustedCAMethods {
		if _, ok := got[name]; !ok {
			t.Errorf("TrustedCA lost method %q: this is a breaking change to the "+
				"public SDK alias, most likely a sub-interface dropped from the composition", name)
		}
	}
	for name := range got {
		if _, ok := trustedCAMethods[name]; !ok {
			t.Errorf("TrustedCA gained method %q without updating trustedCAMethods: "+
				"additions to a public interface break every downstream implementor", name)
		}
	}
	if len(got) != len(trustedCAMethods) {
		t.Errorf("TrustedCA has %d methods, want %d", len(got), len(trustedCAMethods))
	}
}

// TestCA_SatisfiesEverySubInterface states each sub-interface explicitly.
//
// `var _ TrustedCA = (*CA)(nil)` already proves this transitively today, but it
// stops proving it for any interface that is removed from the composition --
// which is precisely when a consumer that depends on the narrow interface would
// break. Naming them individually keeps each one independently enforced.
func TestCA_SatisfiesEverySubInterface(t *testing.T) {
	var _ CAAttestation = (*CA)(nil)
	var _ CACertificateAccessor = (*CA)(nil)
	var _ CAChainImporter = (*CA)(nil)
	var _ CACrossSigner = (*CA)(nil)
	var _ CAIdentityInfo = (*CA)(nil)
	var _ CAIssuer = (*CA)(nil)
	var _ CALifecycle = (*CA)(nil)
	var _ CAObjectStore = (*CA)(nil)
	var _ CARevoker = (*CA)(nil)
	var _ CASigningIdentity = (*CA)(nil)
	var _ CAStores = (*CA)(nil)
	var _ CATCGEnrollment = (*CA)(nil)
	var _ CATLSConfig = (*CA)(nil)
	var _ CATrustChain = (*CA)(nil)
	var _ CATrustPools = (*CA)(nil)
}
