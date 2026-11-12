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

package keybackend

import (
	"testing"

	"github.com/stretchr/testify/require"

	pkgkb "github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
)

// TestReexport_AttestationNames proves the attestation names are aliases of
// the pkg names: the error values are identical (errors.Is holds across both
// import paths) and the function and constants behave the same.
func TestReexport_AttestationNames(t *testing.T) {
	require.Same(t, pkgkb.ErrAttestationCertInvalid, ErrAttestationCertInvalid)
	require.Same(t, pkgkb.ErrAttestationAAGUIDMismatch, ErrAttestationAAGUIDMismatch)

	require.Equal(t, pkgkb.AttestationCertificateOU, AttestationCertificateOU)
	require.True(t, OIDFIDOGenCEAAGUID.Equal(pkgkb.OIDFIDOGenCEAAGUID))

	aaguid := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	got, err := MarshalAAGUIDExtensionValue(aaguid)
	want, wantErr := pkgkb.MarshalAAGUIDExtensionValue(aaguid)
	require.NoError(t, wantErr)
	require.NoError(t, err)
	require.Equal(t, want, got)

	_, err = MarshalAAGUIDExtensionValue(aaguid[:15])
	require.Error(t, err)
	_, wantErr = pkgkb.MarshalAAGUIDExtensionValue(aaguid[:15])
	require.Error(t, wantErr)
}
