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

package main

// go-xkms#705: enrollmentToAuthFactor's FIDO2 credential_id decode failure
// (init_factor_persister.go) was reachable only through
// TestEnrollmentToAuthFactor_FIDO2_MissingCredentialID's empty-string case,
// never through a credential_id that is present but not valid unpadded
// base64url -- a qrdb node record a caller (or a corrupted enrollment) could
// hand back verbatim.

import (
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// TestEnrollmentToAuthFactor_FIDO2_InvalidCredentialIDEncoding proves a
// credential_id that fails base64.RawURLEncoding decoding is refused with a
// *FactorConversionError wrapping the decode error, rather than persisting a
// garbage Credential or panicking.
func TestEnrollmentToAuthFactor_FIDO2_InvalidCredentialIDEncoding(t *testing.T) {
	enrollment := &qrdbsdk.AuthFactorEnrollment{
		FactorName: "fido2",
		PublicKey:  []byte("cose-public-key"),
		Metadata: map[string]string{
			"credential_id": "not-valid-base64url!!!",
			"rp_id":         "xkms.example.com",
		},
	}

	req, err := enrollmentToAuthFactor(7, qrdbsdk.FactorFIDO2, enrollment)
	if req != nil {
		t.Fatalf("enrollmentToAuthFactor with malformed credential_id = %#v, want nil request", req)
	}
	var convErr *FactorConversionError
	if !errors.As(err, &convErr) {
		t.Fatalf("enrollmentToAuthFactor error = %T, want *FactorConversionError", err)
	}
	if convErr.Reason != "decoding credential_id" {
		t.Errorf("Reason = %q, want %q", convErr.Reason, "decoding credential_id")
	}
	if convErr.Err == nil {
		t.Error("expected the underlying base64 decode error to be preserved")
	}
}
