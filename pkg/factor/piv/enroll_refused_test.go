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

package piv

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// A refused enrollment (no tenant) into an occupied slot leaves the existing
// key in place: the enrolled holder still answers its challenge.
func TestPIVFactor_Enroll_RefusedEnrollmentKeepsExistingKey(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1", TenantID: "tenant-t"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	_, err = f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll without tenant err = %v, want AuthFactorEnrollmentInvalidError", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	sig, err := f.SignChallenge(ctx, pivcert.PIVSlotAuthentication, challenge.ChallengeID, "", challenge.Nonce)
	if err != nil {
		t.Fatalf("SignChallenge: %v", err)
	}
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); err != nil {
		t.Fatalf("existing enrollment no longer verifies after a refused enrollment: %v", err)
	}
}
