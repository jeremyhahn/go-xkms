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

package deviceattest01

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/challenges/validation"
)

// loopbackClient returns a validation client that may reach the loopback
// httptest servers these tests run against.
func loopbackClient() *validation.Client {
	return validation.NewClient(validation.Config{AllowPrivateTargets: true})
}

// TestVerifyAttestation_RefusesReservedTarget proves the production client
// will not fetch an attestation from a reserved address.
func TestVerifyAttestation_RefusesReservedTarget(t *testing.T) {
	_, err := VerifyAttestation(validation.NewClient(validation.Config{}), &mockCA{}, "169.254.169.254", "80", "token", "keyauth")
	var verr *validation.Error
	if !errors.As(err, &verr) || verr.Kind != validation.KindTargetRefused {
		t.Fatalf("VerifyAttestation() error = %v, want a KindTargetRefused *validation.Error", err)
	}
}
