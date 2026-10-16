// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	pkgca "github.com/jeremyhahn/go-xkms/pkg/ca"
)

// TestCodeSigningReExports_AliasPkgCA guards the code-signing re-exports
// against drifting from pkg/ca: a consumer matching an SDK error with
// errors.Is must match exactly what pkg/ca returns.
func TestCodeSigningReExports_AliasPkgCA(t *testing.T) {
	if ProfileNameCodeSigning != pkgca.ProfileNameCodeSigning {
		t.Fatalf("ProfileNameCodeSigning = %q, want %q", ProfileNameCodeSigning, pkgca.ProfileNameCodeSigning)
	}
	errorCases := map[string]struct{ sdk, canonical error }{
		"ErrCASubjectNotCommonNameOnly":   {ErrCASubjectNotCommonNameOnly, pkgca.ErrSubjectNotCommonNameOnly},
		"ErrCASubjectAltNameNotPermitted": {ErrCASubjectAltNameNotPermitted, pkgca.ErrSubjectAltNameNotPermitted},
		"ErrCACARequestNotPermitted":      {ErrCACARequestNotPermitted, pkgca.ErrCARequestNotPermitted},
		"ErrCAKeyUsageNotPermitted":       {ErrCAKeyUsageNotPermitted, pkgca.ErrKeyUsageNotPermitted},
		"ErrCAExtKeyUsageNotPermitted":    {ErrCAExtKeyUsageNotPermitted, pkgca.ErrExtKeyUsageNotPermitted},
		"ErrCABoundKeyNotFound":           {ErrCABoundKeyNotFound, pkgca.ErrBoundKeyNotFound},
		"ErrCABoundKeyMismatch":           {ErrCABoundKeyMismatch, pkgca.ErrBoundKeyMismatch},
	}
	for name, tc := range errorCases {
		if tc.sdk != tc.canonical {
			t.Errorf("%s does not alias pkg/ca", name)
		}
	}
	if reflect.TypeFor[CSRValidator]() != reflect.TypeFor[pkgca.CSRValidator]() {
		t.Error("CSRValidator does not alias pkg/ca")
	}
	if _, ok := pkgca.NewCodeSigningProfile().(CSRValidator); !ok {
		t.Error("the code-signing profile does not implement CSRValidator")
	}
}

// TestSDK_CodeSigningProfile signs a conforming CSR through the SDK names
// alone, and checks a bound key the keystore does not hold is refused with
// the SDK error.
func TestSDK_CodeSigningProfile(t *testing.T) {
	ctx := context.Background()
	trustedCA := newSDKTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := sdkCSR(t, key)

	_, err = trustedCA.SignCSR(ctx, csr, &TrustedCASignOptions{Profile: ProfileNameCodeSigning})
	if !errors.Is(err, ErrCATenantRequired) {
		t.Fatalf("no tenant: err = %v, want ErrCATenantRequired", err)
	}

	cert, err := trustedCA.SignCSR(ctx, csr, &TrustedCASignOptions{TenantID: sdkTestTenant, Profile: ProfileNameCodeSigning})
	if err != nil {
		t.Fatalf("sign under %s: %v", ProfileNameCodeSigning, err)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Errorf("ExtKeyUsage = %v, want [codeSigning]", cert.ExtKeyUsage)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != sdkTestTenant {
		t.Errorf("OU = %v, want the tenant %q first", cert.Subject.OrganizationalUnit, sdkTestTenant)
	}

	_, err = trustedCA.SignCSR(ctx, csr, &TrustedCASignOptions{
		TenantID: sdkTestTenant,
		Profile:  ProfileNameCodeSigning,
		BoundKey: &KeyAttributes{
			CN:            "never-generated",
			StoreType:     StoreSoftware,
			KeyType:       KeyTypeSigning,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &ECCAttributes{Curve: elliptic.P256()},
		},
	})
	if !errors.Is(err, ErrCABoundKeyNotFound) {
		t.Fatalf("err = %v, want ErrCABoundKeyNotFound", err)
	}
}
