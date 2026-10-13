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

package ca

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// codeSigningCSR builds a PEM CSR over key from template, which carries the
// subject, names and requested extensions under test.
func codeSigningCSR(t *testing.T, key crypto.Signer, template *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// requestedExtension marshals value into a CSR extension request.
func requestedExtension(t *testing.T, id asn1.ObjectIdentifier, value any) pkix.Extension {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	require.NoError(t, err)
	return pkix.Extension{Id: id, Value: encoded}
}

// digitalSignatureOnly is a key usage BIT STRING asserting digitalSignature.
var digitalSignatureOnly = asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}

func TestCodeSigning_SignsConformingCSR(t *testing.T) {
	c := setupTestCA(t)
	key := newECKey(t, elliptic.P256())
	csr := codeSigningCSR(t, key, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "firmware signer"},
		ExtraExtensions: []pkix.Extension{
			requestedExtension(t, oidKeyUsageExt, digitalSignatureOnly),
			requestedExtension(t, oidExtKeyUsageExt, []asn1.ObjectIdentifier{oidKPCodeSigning}),
			requestedExtension(t, oidBasicConstraintsExt, struct{}{}),
		},
	})

	cert, err := c.SignCSR(context.Background(), csr, &SignOptions{Profile: ProfileNameCodeSigning})
	require.NoError(t, err)

	assert.Equal(t, "firmware signer", cert.Subject.CommonName)
	assert.Len(t, cert.Subject.Names, 1)
	assert.Equal(t, x509.KeyUsageDigitalSignature, cert.KeyUsage)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, cert.ExtKeyUsage)
	assert.True(t, cert.BasicConstraintsValid)
	assert.False(t, cert.IsCA)
	assert.Empty(t, cert.DNSNames)
	assert.Empty(t, cert.EmailAddresses)
	assert.Empty(t, cert.IPAddresses)
	assert.Empty(t, cert.URIs)
	assert.Equal(t, codeSigningDefaultLifetime, cert.NotAfter.Sub(cert.NotBefore))
}

func TestCodeSigning_IssuesAtTheLifetimeBound(t *testing.T) {
	c := setupTestCA(t)
	csr := codeSigningCSR(t, newECKey(t, elliptic.P256()), &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "firmware signer"},
	})

	cert, err := c.SignCSR(context.Background(), csr, &SignOptions{
		Profile:  ProfileNameCodeSigning,
		Validity: codeSigningMaxLifetime,
	})
	require.NoError(t, err)
	assert.Equal(t, codeSigningMaxLifetime, cert.NotAfter.Sub(cert.NotBefore))
}

func TestCodeSigning_Refusals(t *testing.T) {
	c := setupTestCA(t)
	key := newECKey(t, elliptic.P256())
	cnOnly := pkix.Name{CommonName: "firmware signer"}

	tests := []struct {
		name string
		csr  *x509.CertificateRequest
		opts SignOptions
		want error
	}{
		{
			name: "subject carries an organization",
			csr:  &x509.CertificateRequest{Subject: pkix.Name{CommonName: "firmware signer", Organization: []string{"Example"}}},
			want: ErrSubjectNotCommonNameOnly,
		},
		{
			name: "subject has no common name",
			csr:  &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"Example"}}},
			want: ErrSubjectNotCommonNameOnly,
		},
		{
			name: "subject is empty",
			csr:  &x509.CertificateRequest{},
			want: ErrSubjectNotCommonNameOnly,
		},
		{
			name: "CSR requests a DNS name",
			csr:  &x509.CertificateRequest{Subject: cnOnly, DNSNames: []string{"signer.example.com"}},
			want: ErrSubjectAltNameNotPermitted,
		},
		{
			name: "CSR requests a CA certificate",
			csr: &x509.CertificateRequest{Subject: cnOnly, ExtraExtensions: []pkix.Extension{
				requestedExtension(t, oidBasicConstraintsExt, struct{ IsCA bool }{true}),
			}},
			want: ErrCARequestNotPermitted,
		},
		{
			name: "CSR basic constraints do not decode",
			csr: &x509.CertificateRequest{Subject: cnOnly, ExtraExtensions: []pkix.Extension{
				{Id: oidBasicConstraintsExt, Value: []byte{0x01}},
			}},
			want: ErrCARequestNotPermitted,
		},
		{
			name: "CSR requests keyEncipherment",
			csr: &x509.CertificateRequest{Subject: cnOnly, ExtraExtensions: []pkix.Extension{
				requestedExtension(t, oidKeyUsageExt, asn1.BitString{Bytes: []byte{0xA0}, BitLength: 3}),
			}},
			want: ErrKeyUsageNotPermitted,
		},
		{
			name: "CSR requests serverAuth",
			csr: &x509.CertificateRequest{Subject: cnOnly, ExtraExtensions: []pkix.Extension{
				requestedExtension(t, oidExtKeyUsageExt, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}}),
			}},
			want: ErrExtKeyUsageNotPermitted,
		},
		{
			name: "CSR requests codeSigning beside serverAuth",
			csr: &x509.CertificateRequest{Subject: cnOnly, ExtraExtensions: []pkix.Extension{
				requestedExtension(t, oidExtKeyUsageExt, []asn1.ObjectIdentifier{oidKPCodeSigning, {1, 3, 6, 1, 5, 5, 7, 3, 1}}),
			}},
			want: ErrExtKeyUsageNotPermitted,
		},
		{
			name: "lifetime above the bound",
			csr:  &x509.CertificateRequest{Subject: cnOnly},
			opts: SignOptions{Validity: codeSigningMaxLifetime + time.Hour},
			want: ErrValidityExceedsProfile,
		},
		{
			name: "day count above the bound",
			csr:  &x509.CertificateRequest{Subject: cnOnly},
			opts: SignOptions{ValidityDays: 461},
			want: ErrValidityExceedsProfile,
		},
		{
			name: "caller adds subject alternative names",
			csr:  &x509.CertificateRequest{Subject: cnOnly},
			opts: SignOptions{SANS: &SubjectAlternativeNames{DNS: []string{"signer.example.com"}}},
			want: ErrSubjectAltNameNotPermitted,
		},
		{
			name: "caller adds a subject attribute",
			csr:  &x509.CertificateRequest{Subject: cnOnly},
			opts: SignOptions{Subject: &Subject{Organization: "Example"}},
			want: ErrSubjectNotCommonNameOnly,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			opts.Profile = ProfileNameCodeSigning
			_, err := c.SignCSR(context.Background(), codeSigningCSR(t, key, tt.csr), &opts)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestCodeSigning_RefusesMalformedRequestedExtensions(t *testing.T) {
	profile := NewCodeSigningProfile().(CSRValidator)
	malformed := []byte{0xFF}
	tests := []struct {
		id   asn1.ObjectIdentifier
		want error
	}{
		{oidKeyUsageExt, ErrKeyUsageNotPermitted},
		{oidExtKeyUsageExt, ErrExtKeyUsageNotPermitted},
		{oidBasicConstraintsExt, ErrCARequestNotPermitted},
	}
	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			err := profile.ValidateCSR(&x509.CertificateRequest{
				Subject:    pkix.Name{CommonName: "firmware signer"},
				Extensions: []pkix.Extension{{Id: tt.id, Value: malformed}},
			})
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestCodeSigning_RefusesUndecodableSubject(t *testing.T) {
	profile := NewCodeSigningProfile().(CSRValidator)
	err := profile.ValidateCSR(&x509.CertificateRequest{RawSubject: []byte{0x30, 0x05}})
	require.ErrorIs(t, err, ErrSubjectNotCommonNameOnly)
}

func TestCodeSigning_TemplateRefusesEncodedSubjectAltName(t *testing.T) {
	profile := NewCodeSigningProfile().(TemplateValidator)
	err := profile.ValidateTemplate(&x509.Certificate{
		Subject:         pkix.Name{CommonName: "firmware signer"},
		ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltNameExt, Value: []byte{0x30, 0x00}}},
	})
	require.ErrorIs(t, err, ErrSubjectAltNameNotPermitted)
}

// boundSoftwareKey generates an ECDSA key in the CA's software keystore and
// returns the attributes that name it and its signer.
func boundSoftwareKey(t *testing.T, c *CA, cn string) (*types.KeyAttributes, crypto.Signer) {
	t.Helper()
	ctx := context.Background()
	attrs := &types.KeyAttributes{
		CN:            cn,
		StoreType:     types.StoreSoftware,
		KeyType:       types.KeyTypeSigning,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	_, err := c.keyStore.GenerateECDSA(ctx, attrs)
	require.NoError(t, err)
	signer, err := c.keyStore.Signer(ctx, attrs)
	require.NoError(t, err)
	return attrs, signer
}

func TestSignCSR_BoundKeyMatches(t *testing.T) {
	c := setupTestCA(t)
	attrs, signer := boundSoftwareKey(t, c, "boot-signer")
	csr := codeSigningCSR(t, signer, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "boot-signer"}})

	cert, err := c.SignCSR(context.Background(), csr, &SignOptions{Profile: ProfileNameCodeSigning, BoundKey: attrs})
	require.NoError(t, err)

	want, err := x509.MarshalPKIXPublicKey(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, want, cert.RawSubjectPublicKeyInfo)
}

func TestSignCSR_BoundKeyMismatch(t *testing.T) {
	c := setupTestCA(t)
	attrs, _ := boundSoftwareKey(t, c, "boot-signer")
	csr := codeSigningCSR(t, newECKey(t, elliptic.P256()), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "boot-signer"}})

	_, err := c.SignCSR(context.Background(), csr, &SignOptions{Profile: ProfileNameCodeSigning, BoundKey: attrs})
	require.ErrorIs(t, err, ErrBoundKeyMismatch)
}

func TestSignCSR_BoundKeyNotFound(t *testing.T) {
	c := setupTestCA(t)
	csr := codeSigningCSR(t, newECKey(t, elliptic.P256()), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "boot-signer"}})

	_, err := c.SignCSR(context.Background(), csr, &SignOptions{
		Profile: ProfileNameCodeSigning,
		BoundKey: &types.KeyAttributes{
			CN:            "never-generated",
			StoreType:     types.StoreSoftware,
			KeyType:       types.KeyTypeSigning,
			KeyAlgorithm:  x509.ECDSA,
			ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		},
	})
	require.ErrorIs(t, err, ErrBoundKeyNotFound)
}
