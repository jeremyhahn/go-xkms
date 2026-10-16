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

package ca_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// TestTimestampingProfile_CriticalExtKeyUsage pins RFC 3161 section 2.3 on a
// certificate the CA issues under the timestamping profile: one extended key
// usage extension, marked critical, listing id-kp-timeStamping alone.
func TestTimestampingProfile_CriticalExtKeyUsage(t *testing.T) {
	trustedCA := newIssuingCA(t, rootOnlyConfig(t, "Timestamping Root CA"), nil)

	cert, err := trustedCA.SignCSR(context.Background(), generateCSR(t, "tsa.example.com"), &ca.SignOptions{
		TenantID: e2eTenant,
		Profile:  ca.NewTimestampingProfile().Name(),
	})
	require.NoError(t, err)
	reparsed, err := x509.ParseCertificate(cert.Raw)
	require.NoError(t, err)
	require.NotEmpty(t, reparsed.Subject.OrganizationalUnit)
	assert.Equal(t, e2eTenant, reparsed.Subject.OrganizationalUnit[0])

	extension, count := certificateExtension(reparsed, oidExtKeyUsage)
	require.Equal(t, 1, count, "the extended key usage extension must be encoded once")
	assert.True(t, extension.Critical)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, reparsed.ExtKeyUsage)
	assert.Empty(t, reparsed.UnknownExtKeyUsage)
	assert.NotZero(t, reparsed.KeyUsage&x509.KeyUsageDigitalSignature)
}

// TestTimestampingProfile_ReplacesExistingExtKeyUsage pins that an extended
// key usage extension already on the template is replaced, not duplicated.
func TestTimestampingProfile_ReplacesExistingExtKeyUsage(t *testing.T) {
	serverAuth, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 1}})
	require.NoError(t, err)
	template := &x509.Certificate{
		ExtraExtensions: []pkix.Extension{{Id: oidExtKeyUsage, Value: serverAuth}},
	}

	require.NoError(t, ca.NewTimestampingProfile().Apply(template, nil))

	require.Len(t, template.ExtraExtensions, 1)
	extension := template.ExtraExtensions[0]
	assert.True(t, extension.Critical)
	var usages []asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(extension.Value, &usages)
	require.NoError(t, err)
	assert.Equal(t, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}, usages)
}

func TestTimestampingProfile_ApplyRejectsNilTemplate(t *testing.T) {
	assert.ErrorIs(t, ca.NewTimestampingProfile().Apply(nil, nil), ca.ErrInvalidProfile)
}
