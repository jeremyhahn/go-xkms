// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"context"
	"errors"
	"fmt"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCertificateAbsentDoesNotReadFailuresAsAbsence is #313 site 1.
//
// `DeleteCertificate` removes BOTH the certificate and the key, and decides
// whether a failed certificate delete blocks the key delete. That decision used
// to be `strings.Contains(err.Error(), "not found")`, which is a fail-open:
// a permission error, a backend path error or a missing BACKEND all contain
// that phrase, so any of them read as "no certificate, carry on" and the slot
// was reported empty while still holding a certificate.
//
// The rows below are the ones that used to be misread. The local arm
// (remoteMessage=false) is in-process, so the sentinel is always reachable and
// nothing is decided on text at all.
func TestCertificateAbsentDoesNotReadFailuresAsAbsence(t *testing.T) {
	misreadBefore := []struct {
		name string
		err  error
	}{
		{"permission error naming a path", errors.New("open /var/lib/xkey/piv: permission denied: not found")},
		{"the BACKEND is missing, not the certificate", errors.New("backend not found: tpm2")},
		{"a key, not a certificate", errors.New("key not found: piv-9a")},
		{"a slot the store does not know", errors.New("slot not found: 9z")},
	}

	for _, tc := range misreadBefore {
		for _, remote := range []bool{false, true} {
			arm := "local"
			if remote {
				arm = "remote"
			}
			t.Run(arm+"/"+tc.name, func(t *testing.T) {
				assert.False(t, certificateAbsent(tc.err, remote),
					"a failure that is not the sentinel must block the key delete, got absent for %v", tc.err)
			})
		}
	}

	// The real sentinel is recognised on both arms, wrapped or not — that is
	// the case the gate exists to let through.
	wrapped := xkms.NewPIVStorageError("Delete", xkms.PIVSlotAuthentication, xkms.ErrPIVCertificateNotFound)
	for _, remote := range []bool{false, true} {
		assert.True(t, certificateAbsent(xkms.ErrPIVCertificateNotFound, remote),
			"the bare sentinel is absence (remote=%v)", remote)
		assert.True(t, certificateAbsent(wrapped, remote),
			"PIVStorageError unwraps to the sentinel, which is what every local backend returns (remote=%v)", remote)
		assert.True(t, certificateAbsent(fmt.Errorf("delete: %w", xkms.ErrPIVCertificateNotFound), remote),
			"a caller-wrapped sentinel is still absence (remote=%v)", remote)
	}

	assert.False(t, certificateAbsent(nil, true), "no error is not an absent certificate")
	assert.False(t, certificateAbsent(nil, false), "no error is not an absent certificate")
}

// TestCertificateAbsentRemoteArmMatchesOnlyTheSentinelText pins the one
// difference between the arms, so it reads as deliberate.
//
// Error identity does not cross the wire for this call: pkg/api/transport's
// ErrorCode vocabulary describes the CONNECTION (NotConnected, Timeout,
// TLSHandshakeFailed) and has no code meaning "the resource was absent". What
// DOES cross is the message: the server puts the error text in the response
// body (handlePIVError -> writeError), and a missing certificate renders with
// the sentinel's own string in it. So the remote arm matches exactly that and
// nothing looser -- everything else fails CLOSED, reporting the delete rather
// than deleting the key and calling the slot empty.
func TestCertificateAbsentRemoteArmMatchesOnlyTheSentinelText(t *testing.T) {
	remoteShape := errors.New("pivcert: Delete slot 9a: " + xkms.ErrPIVCertificateNotFound.Error())
	assert.True(t, certificateAbsent(remoteShape, true),
		"the shape the server actually sends must be recognised")
	assert.False(t, certificateAbsent(remoteShape, false),
		"the in-process arm decides on the sentinel value, never on text")

	for _, err := range []error{
		errors.New("backend not found: tpm2"),
		errors.New("key not found: piv-9a"),
		errors.New("open /var/lib/xkey/piv: permission denied: not found"),
		errors.New("certificate missing"),
	} {
		assert.False(t, certificateAbsent(err, true),
			"the remote arm must not accept %q as an absent certificate", err)
	}
}

// TestKeyListingFailureNeverReportsSuccess is the second review finding: the
// certificate was deleted, the key listing failed, and DeleteCertificate
// returned nil -- success for an operation whose second half was never
// attempted, against a contract that says the slot now holds neither.
//
// Both the remote and the in-process path ask this one function, so this
// covers the decision on both.
func TestKeyListingFailureNeverReportsSuccess(t *testing.T) {
	listErr := errors.New("list keys: backend unavailable")

	t.Run("certificate was deleted", func(t *testing.T) {
		err := keyListingFailure("9a", false, listErr)
		require.Error(t, err, "a listing failure is never success")
		assert.ErrorIs(t, err, listErr, "the cause must survive for the caller to act on")
		assert.False(t, errors.Is(err, ErrPIVNoCertificate),
			"the certificate was present and deleted; this is not the absent case")
		assert.Contains(t, err.Error(), "the key may remain",
			"the operator must be told what is unresolved")
	})

	t.Run("certificate was already absent", func(t *testing.T) {
		err := keyListingFailure("9a", true, listErr)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPIVNoCertificate,
			"an absent certificate keeps its own sentinel for the caller that distinguishes it")
		// Both causes, or the listing failure is reachable only by reading the
		// message: a caller asking errors.Is would see a benign "no
		// certificate" and lose the fact that the key was never inspected.
		assert.ErrorIs(t, err, listErr,
			"the listing failure must survive errors.Is alongside the absent-certificate sentinel")
		assert.Contains(t, err.Error(), "the key may remain")
	})

	t.Run("the two causes stay distinguishable", func(t *testing.T) {
		// The joined error must not make every listing failure look absent, nor
		// every absent certificate look like a listing failure.
		deleted := keyListingFailure("9a", false, listErr)
		assert.ErrorIs(t, deleted, listErr)
		assert.False(t, errors.Is(deleted, ErrPIVNoCertificate),
			"a deleted certificate is not the absent case")
	})
}

// TestDeleteCertificateSurfacesARemoteKeyListingFailure proves the decision is
// actually wired into the remote path, rather than only being correct in
// isolation. mockPIVClient accepts the certificate delete and always fails
// ListKeys, which is exactly the sequence the finding describes.
func TestDeleteCertificateSurfacesARemoteKeyListingFailure(t *testing.T) {
	svc := NewPIVService(&mockPIVClient{deletePIVCertErr: nil}, "software")
	svc.SetContext(context.Background())

	err := svc.DeleteCertificate("9a")

	require.Error(t, err, "the certificate was deleted and the key was never inspected; that is not success")
	assert.Contains(t, err.Error(), "the key may remain")
}
