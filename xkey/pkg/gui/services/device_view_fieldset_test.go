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

package services

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// pairedDeviceViewFieldSource is the reviewed correspondence between the
// Wails-facing view model's fields (PairedDevice, this package) and the
// persisted record's fields (pairing.PairedDevice) they project.
//
// An empty source means the view field is computed at call time rather than
// read off the record — Connected is live connection state, never written to
// devices.yaml. Every other view field must name the persisted field
// deviceView actually reads.
var pairedDeviceViewFieldSource = map[string]string{
	"Name":      "Name",
	"Address":   "Address",
	"PairedAt":  "PairedAt",
	"LastSeen":  "LastDeviceAttestationTime",
	"Connected": "",
	"IsBackend": "IsBackend",
}

// pairedDevicePersistedOnlyFields is the reviewed, explicit allowlist of
// pairing.PairedDevice fields that have no counterpart in the GUI's view
// model: key material, attestation internals and per-device policy the
// frontend never displays directly.
var pairedDevicePersistedOnlyFields = map[string]bool{
	"NoisePublicKey":             true,
	"LocalNoisePrivateKey":       true,
	"DeviceBootHashHex":          true,
	"AttestationGracePeriod":     true,
	"SecurityLevel":              true,
	"BootStateVerified":          true,
	"DeviceFingerprint":          true,
	"AttestationProtocolVersion": true,
	"LastAttestation":            true,
	"AttestationPolicy":          true,
}

// TestPairedDeviceViewReflectsExactlyTheRecordsFieldSet is the test #130(b)
// requires: one that fails on the drift mechanism itself, not on today's
// instance of it. Three times running — #95, #124 round 1, and the GUI's
// own mirror before this unification — a field existed on one paired-device
// struct and not on another, and nothing caught it until a device silently
// read as unbound. Unifying the persisted record into one type (#130)
// removed the CLI/GUI half of that; this test removes the other half, the
// GUI's view model quietly drifting from the record it projects.
//
// It fails in either direction:
//   - a view field with no declared source (added to the view without
//     deciding what it projects, or projecting a persisted field that no
//     longer exists), and
//   - a persisted field that is neither projected into the view nor on the
//     reviewed persisted-only allowlist (added to the record without anyone
//     deciding whether the frontend should see it).
//
// A stale allowlist entry — naming a field the record no longer has — also
// fails, so the allowlist itself cannot rot into a blanket exemption.
func TestPairedDeviceViewReflectsExactlyTheRecordsFieldSet(t *testing.T) {
	recordType := reflect.TypeOf(pairing.PairedDevice{})
	viewType := reflect.TypeOf(PairedDevice{})

	recordFields := make(map[string]bool, recordType.NumField())
	for i := 0; i < recordType.NumField(); i++ {
		recordFields[recordType.Field(i).Name] = true
	}

	viewFields := make(map[string]bool, viewType.NumField())
	for i := 0; i < viewType.NumField(); i++ {
		viewFields[viewType.Field(i).Name] = true
	}

	projected := make(map[string]bool, len(pairedDeviceViewFieldSource))
	for viewField, source := range pairedDeviceViewFieldSource {
		require.True(t, viewFields[viewField],
			"pairedDeviceViewFieldSource names %q, which does not exist on the view "+
				"model PairedDevice; remove the stale entry", viewField)
		if source == "" {
			continue
		}
		require.True(t, recordFields[source],
			"view field %q claims to project persisted field %q, which does not exist "+
				"on pairing.PairedDevice; update pairedDeviceViewFieldSource and deviceView",
			viewField, source)
		projected[source] = true
	}

	// Every view field must have a declared source — mapped to a persisted
	// field, or explicitly computed. A view field with nothing declared is
	// exactly the drift this test exists to catch: a projection nobody
	// reviewed against the record.
	for viewField := range viewFields {
		_, declared := pairedDeviceViewFieldSource[viewField]
		require.True(t, declared,
			"view field %q has no entry in pairedDeviceViewFieldSource; either wire it to "+
				"the persisted field deviceView reads, or record \"\" if it is computed rather "+
				"than persisted", viewField)
	}

	// Every persisted field must be either projected into the view (above)
	// or on the reviewed persisted-only allowlist. A field in neither is the
	// #95 / #124 shape: something the record carries that nobody decided
	// whether the view should show.
	for recordField := range recordFields {
		if projected[recordField] {
			continue
		}
		require.True(t, pairedDevicePersistedOnlyFields[recordField],
			"persisted field %q is neither projected into the GUI view model (via "+
				"pairedDeviceViewFieldSource) nor on the reviewed persisted-only allowlist "+
				"(pairedDevicePersistedOnlyFields); decide whether deviceView should show it "+
				"and update one of the two", recordField)
	}

	// And the reverse: an allowlist entry naming a field the record no
	// longer has would silently stop checking anything.
	for allowed := range pairedDevicePersistedOnlyFields {
		require.True(t, recordFields[allowed],
			"pairedDevicePersistedOnlyFields names %q, which does not exist on "+
				"pairing.PairedDevice; remove the stale entry", allowed)
	}
}
