// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// sdkTestTenant is the tenant the SDK tests' leaf certificates are bound to.
const sdkTestTenant = "tenant-sdk"

// newSDKTestCA builds an initialized in-memory TrustedCA using only the SDK's
// exported names, the way a consumer of this module does.
func newSDKTestCA(t *testing.T) TrustedCA {
	t.Helper()
	sw, err := NewSoftwareBackend(&SoftwareBackendConfig{KeyStorage: NewStorageMemory()})
	if err != nil {
		t.Fatalf("software backend: %v", err)
	}
	keyStore, err := NewServiceBackend(&ServiceBackendConfig{Backend: sw, CertStorage: NewStorageMemory()})
	if err != nil {
		t.Fatalf("service backend: %v", err)
	}
	certs, err := NewCertStore(&CertStoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	if err != nil {
		t.Fatalf("cert store: %v", err)
	}
	config := DefaultMultiIdentityCAConfig()
	config.Identity[0].Subject.CommonName = "SDK Root CA"
	config.Identity[0].Keys[0].KeyType = "CA"

	trustedCA, err := NewTrustedCAFromMultiIdentityConfig(&TrustedCAMultiIdentityParams{
		Config:   config,
		KeyStore: keyStore,
		BackendForStore: func(string, StoreType) (ServiceBackend, error) {
			return keyStore, nil
		},
		RevocationStore: NewStorageMemory(),
		CertStore:       certs,
	})
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	if err := trustedCA.Init(context.Background()); err != nil {
		t.Fatalf("init CA: %v", err)
	}
	return trustedCA
}

func sdkCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "from-csr"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSDK_OverlayProfilesUnderNameConstrainedSubordinates(t *testing.T) {
	ctx := context.Background()
	trustedCA := newSDKTestCA(t)
	subIssuer, ok := trustedCA.(SubordinateIssuer)
	if !ok {
		t.Fatalf("%T does not implement SubordinateIssuer", trustedCA)
	}
	root, err := trustedCA.CACertificate()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	verify := func(leaf, intermediate *x509.Certificate) error {
		inter := x509.NewCertPool()
		inter.AddCert(intermediate)
		_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		return err
	}

	t.Run("ipsec-vtep", func(t *testing.T) {
		_, fabric, _ := net.ParseCIDR("10.4.0.0/24")
		tunnelKey := newKey()
		tunnel, err := subIssuer.IssueSubordinateCA(ctx, &SubordinateCARequest{
			Subject:         pkix.Name{CommonName: "Tunnel Intermediate"},
			PublicKey:       tunnelKey.Public(),
			NameConstraints: &NameConstraints{Critical: true, PermittedIPRanges: []*net.IPNet{fabric}},
		})
		if err != nil {
			t.Fatalf("subordinate: %v", err)
		}
		digest := sha256.Sum256([]byte("pcrs"))
		evidence, err := CreateAttestationEvidenceExtension(AttestationEvidence{
			VerdictID: "v1", PCRDigestAlgorithm: crypto.SHA256, PCRDigest: digest[:], AttestedAt: time.Now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		cert, err := trustedCA.SignCSR(ctx, sdkCSR(t, newKey()), &TrustedCASignOptions{
			TenantID:        sdkTestTenant,
			Profile:         ProfileNameIPsecVTEP,
			Signer:          tunnelKey,
			IssuerCert:      tunnel,
			SANS:            &TrustedCASubjectAlternativeNames{IPs: []string{"10.4.0.7"}},
			ExtraExtensions: []pkix.Extension{evidence},
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if len(cert.UnknownExtKeyUsage) != 1 || !cert.UnknownExtKeyUsage[0].Equal(OIDIPsecIKE) {
			t.Errorf("EKU = %v", cert.UnknownExtKeyUsage)
		}
		if got, ok, err := ParseAttestationEvidenceExtension(cert); err != nil || !ok || got.VerdictID != "v1" {
			t.Errorf("evidence = %+v %v %v", got, ok, err)
		}
		if err := verify(cert, tunnel); err != nil {
			t.Errorf("verify: %v", err)
		}

		_, err = trustedCA.SignCSR(ctx, sdkCSR(t, newKey()), &TrustedCASignOptions{
			TenantID: sdkTestTenant,
			Profile:  ProfileNameIPsecVTEP, Signer: tunnelKey, IssuerCert: tunnel,
			SANS: &TrustedCASubjectAlternativeNames{IPs: []string{"192.0.2.1"}},
		})
		if !errors.Is(err, ErrCANameConstraintViolation) {
			t.Errorf("outside constraints: err = %v", err)
		}
	})

	t.Run("x509-svid", func(t *testing.T) {
		svidKey := newKey()
		svidCA, err := subIssuer.IssueSubordinateCA(ctx, &SubordinateCARequest{
			Subject:         pkix.Name{CommonName: "SPIFFE Intermediate"},
			PublicKey:       svidKey.Public(),
			NameConstraints: &NameConstraints{Critical: true, PermittedURIDomains: []string{sdkTestTenant}},
		})
		if err != nil {
			t.Fatalf("subordinate: %v", err)
		}
		cert, err := trustedCA.SignCSR(ctx, sdkCSR(t, newKey()), &TrustedCASignOptions{
			TenantID:   sdkTestTenant,
			Profile:    ProfileNameX509SVID,
			Signer:     svidKey,
			IssuerCert: svidCA,
			SANS:       &TrustedCASubjectAlternativeNames{URIs: []string{"spiffe://tenant-sdk/svc/web"}},
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if len(cert.URIs) != 1 || cert.IsCA || cert.NotAfter.Sub(cert.NotBefore) != time.Hour {
			t.Errorf("URIs=%v IsCA=%v lifetime=%v", cert.URIs, cert.IsCA, cert.NotAfter.Sub(cert.NotBefore))
		}
		if err := verify(cert, svidCA); err != nil {
			t.Errorf("verify: %v", err)
		}

		_, err = trustedCA.SignCSR(ctx, sdkCSR(t, newKey()), &TrustedCASignOptions{
			TenantID: sdkTestTenant,
			Profile:  ProfileNameX509SVID, Signer: svidKey, IssuerCert: svidCA,
		})
		if !errors.Is(err, ErrCACallerSANsRequired) {
			t.Errorf("no caller SANs: err = %v", err)
		}
	})
}
