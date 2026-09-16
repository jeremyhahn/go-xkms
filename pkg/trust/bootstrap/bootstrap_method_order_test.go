// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0)
// for non-commercial use. Commercial licenses are available.
// See LICENSE and LICENSE-COMMERCIAL for details.

package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	"github.com/stretchr/testify/require"
)

// TestTranslateMethodOrder_MapsKnownModes proves the four non-TOFU modes
// round-trip to their go-truststrap Method in the order given, the shape
// Config.MethodOrder needs to reorder or subset the Auto walk.
func TestTranslateMethodOrder_MapsKnownModes(t *testing.T) {
	got := translateMethodOrder([]Mode{ModeSPKI, ModeDANE})
	require.Equal(t, []truststrap.Method{truststrap.MethodSPKI, truststrap.MethodDANE}, got)
}

// TestTranslateMethodOrder_DropsTOFUAndUnknown proves ModeTOFU and any
// unrecognized Mode are dropped rather than surfacing as a truststrap.Method
// zero value — MethodOrder must never become a second way to arm TOFU.
func TestTranslateMethodOrder_DropsTOFUAndUnknown(t *testing.T) {
	got := translateMethodOrder([]Mode{ModeDirect, ModeTOFU, Mode("bogus")})
	require.Equal(t, []truststrap.Method{truststrap.MethodDirect}, got)
}

// TestFetch_AutoMethodOrderExcludesUnlisted proves that a MethodOrder
// omitting an otherwise-armed method keeps that method out of the Auto walk
// entirely — the seam an operator-facing "--method dane,noise" flag needs to
// select or reorder methods without importing go-truststrap for its Method
// type. Both SPKI and Direct are armed and unreachable; only SPKI is listed,
// so the aggregate must record exactly that one attempt.
func TestFetch_AutoMethodOrderExcludesUnlisted(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		ServerURL:        "http://127.0.0.1:1",
		SPKI:             &SPKIConfig{Pin: strings.Repeat("00", 32)},
		Direct:           &DirectConfig{},
		MethodOrder:      []Mode{ModeSPKI},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	require.Error(t, err)
	var agg *truststrap.AggregateError
	require.ErrorAs(t, err, &agg)
	require.Len(t, agg.Attempts, 1)
	require.Equal(t, truststrap.MethodSPKI, agg.Attempts[0].Method)
}

// TestFetch_AutoTOFUMethodOrderTakesPrecedenceOverMethodOrder proves that
// when TOFU is armed, TOFUMethodOrder still governs the walk even if
// MethodOrder is also set — MethodOrder must not weaken the explicit opt-in
// TOFUMethodOrder requires before a TOFU fallback runs.
func TestFetch_AutoTOFUMethodOrderTakesPrecedenceOverMethodOrder(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:             ModeAuto,
		ServerURL:        "http://127.0.0.1:1",
		SPKI:             &SPKIConfig{Pin: strings.Repeat("00", 32)},
		TOFU:             &TOFUConfig{PinStore: truststrap.NewMemoryPinStore()},
		MethodOrder:      []Mode{ModeSPKI},
		TOFUMethodOrder:  []truststrap.Method{truststrap.MethodTOFU},
		PerMethodTimeout: 250 * time.Millisecond,
		Logger:           discardLogger(),
	})
	require.Error(t, err)
	var agg *truststrap.AggregateError
	require.ErrorAs(t, err, &agg)
	require.Len(t, agg.Attempts, 1)
	require.Equal(t, truststrap.MethodTOFU, agg.Attempts[0].Method)
}
