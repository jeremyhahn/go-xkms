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

//go:build awskms

package ca

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// TestGetOrGenerateKey_LostRaceReturnsWinnersKey_AWSKMS is the awskms row of
// TestGetOrGenerateKey_LostRaceReturnsWinnersKey.
func TestGetOrGenerateKey_LostRaceReturnsWinnersKey_AWSKMS(t *testing.T) {
	t.Parallel()
	assertLostRaceReturnsWinnersKey(t, &errs.Detail{Err: awskms.ErrKeyAlreadyExists, Detail: "lost-generate-race.example.com"})
}
