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

//go:build gcpkms

package ca

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TestGetOrGenerateKey_LostRaceReturnsWinnersKey_GCPKMS is the gcpkms row of
// TestGetOrGenerateKey_LostRaceReturnsWinnersKey.
func TestGetOrGenerateKey_LostRaceReturnsWinnersKey_GCPKMS(t *testing.T) {
	t.Parallel()
	assertLostRaceReturnsWinnersKey(t, &errs.Detail{Err: gcpkms.ErrKeyAlreadyExists, Detail: "lost-generate-race.example.com"})
}
