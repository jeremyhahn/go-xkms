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

package certsubject

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

// The pkg/ca tenant_subject tests cover StampTenant through its pkg/ca alias;
// these pin the leaf package's own contract.

func TestStampTenant_ReplacesEveryOrganizationalUnit(t *testing.T) {
	subject := pkix.Name{
		CommonName:         "device-1",
		OrganizationalUnit: []string{"other", "more"},
		ExtraNames:         []pkix.AttributeTypeAndValue{{Type: oidAttributeOrganizationalUnit, Value: "extra"}},
	}
	got, raw, err := StampTenant("acme", subject, nil)
	require.NoError(t, err)
	require.Nil(t, raw)
	require.Equal(t, []string{"acme"}, got.OrganizationalUnit)
	require.Empty(t, got.ExtraNames)
	require.Equal(t, "device-1", got.CommonName)
}

func TestStampTenant_RefusesEmptyTenant(t *testing.T) {
	_, _, err := StampTenant("", pkix.Name{CommonName: "device-1"}, nil)
	require.ErrorIs(t, err, ErrTenantRequired)
}

func TestStampTenant_RawSubject(t *testing.T) {
	rdns := pkix.RDNSequence{
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"}},
		{{Type: oidAttributeCommonName, Value: "node"}},
	}
	raw, err := asn1.Marshal(rdns)
	require.NoError(t, err)

	name, stamped, err := StampTenant("acme", pkix.Name{}, raw)
	require.NoError(t, err)
	require.Equal(t, []string{"acme"}, name.OrganizationalUnit)

	// Already stamped: returned byte for byte.
	_, again, err := StampTenant("acme", pkix.Name{}, stamped)
	require.NoError(t, err)
	require.Equal(t, stamped, again)

	_, _, err = StampTenant("acme", pkix.Name{}, []byte("not a distinguished name"))
	require.ErrorIs(t, err, ErrInvalidRawSubject)
}
