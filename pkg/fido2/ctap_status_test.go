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

package fido2

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusRangeMarkers are the Status* constants in types.go that name the
// boundaries of the extension and vendor code ranges rather than a status an
// authenticator returns. Codes inside those ranges are authenticator-defined,
// so there is no name to map them to and the hex rendering is correct.
var statusRangeMarkers = map[string]bool{
	"StatusSpecLast":       true,
	"StatusExtensionFirst": true,
	"StatusExtensionLast":  true,
	"StatusVendorFirst":    true,
	"StatusVendorLast":     true,
}

// declaredStatuses parses types.go and returns every Status* constant it
// declares, by name. Reading the declarations rather than restating them is
// deliberate: a hand-copied list is a second list that drifts, and the defect
// this guards against — #310 — was precisely a gap between two lists.
func declaredStatuses(t *testing.T) map[string]byte {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "types.go", nil, 0)
	require.NoError(t, err, "types.go must be parseable")

	statuses := make(map[string]byte)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
				continue
			}
			name := value.Names[0].Name
			if !strings.HasPrefix(name, "Status") {
				continue
			}
			lit, ok := value.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				continue
			}
			parsed, err := strconv.ParseUint(lit.Value, 0, 8)
			require.NoErrorf(t, err, "status %s has a value that does not fit a byte", name)
			statuses[name] = byte(parsed)
		}
	}

	require.NotEmpty(t, statuses, "types.go must declare Status constants")
	return statuses
}

// TestCTAPStatusTableCoversEverySpecStatus is the guard that keeps #310 from
// reopening. Every Status* constant declared in types.go must either be in
// ctapStatusErrors or be one of the documented exemptions; a new constant
// added without a mapping fails here rather than reaching an operator as a
// bare hex code.
func TestCTAPStatusTableCoversEverySpecStatus(t *testing.T) {
	for name, status := range declaredStatuses(t) {
		t.Run(name, func(t *testing.T) {
			switch {
			case name == "StatusOK":
				// Never reaches handleCTAPError: sendCBOR calls it only once
				// it has established the status is not StatusOK.
				assert.NotContains(t, ctapStatusErrors, status,
					"StatusOK must not be mapped to an error")
			case statusRangeMarkers[name]:
				assert.NotContains(t, ctapStatusErrors, status,
					"%s is a range boundary, not a status", name)
			default:
				mapped, ok := ctapStatusErrors[status]
				require.Truef(t, ok,
					"%s (0x%02X) is declared but unmapped, so it surfaces as a raw hex code", name, status)
				require.NotNil(t, mapped)
				assert.NotContains(t, mapped.Error(), "CTAP error: 0x",
					"%s must map to a described error, not the hex fallthrough", name)
			}
		})
	}
}

// TestHandleCTAPErrorInvalidOption covers the status #310 was filed for:
// 0x2C is what a PIN-only authenticator answers when a request asks for the
// uv option, and it must arrive as a matchable sentinel.
func TestHandleCTAPErrorInvalidOption(t *testing.T) {
	err := (&CTAPHIDDevice{}).handleCTAPError(StatusInvalidOption)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidOption,
		"a caller must be able to match 0x2C with errors.Is")
	assert.NotContains(t, err.Error(), "CTAP error: 0x2C",
		"0x2C must no longer surface as a raw hex code")
}

// TestHandleCTAPErrorUnknownStatusRendersHex is the bad-input counterpart: a
// code the specification does not define has no name to report, so the hex
// rendering must survive. Without this the fix could be "map everything",
// which would invent names for authenticator-defined codes.
func TestHandleCTAPErrorUnknownStatusRendersHex(t *testing.T) {
	device := &CTAPHIDDevice{}

	for _, status := range []byte{0xE0, 0xE5, 0xEF, 0xF0, 0xF5, 0xFF, 0x50, 0x60} {
		t.Run(fmt.Sprintf("status_0x%02X", status), func(t *testing.T) {
			err := device.handleCTAPError(status)
			require.Error(t, err)
			assert.Equal(t, fmt.Sprintf("CTAP error: 0x%02X", status), err.Error(),
				"an undefined status must render as hex, not as an invented name")
		})
	}
}

// TestHandleCTAPErrorPreservesExistingSentinels pins the mappings that already
// existed before #310. Several are load-bearing for errors.Is matching in the
// ceremony paths, and #310 explicitly forbids changing them, so restating them
// here makes an accidental change fail rather than pass quietly.
func TestHandleCTAPErrorPreservesExistingSentinels(t *testing.T) {
	device := &CTAPHIDDevice{}

	sentinels := map[byte]error{
		StatusTimeout:              ErrOperationTimeout,
		StatusInvalidCBOR:          ErrInvalidCBOR,
		StatusUnsupportedExtension: ErrUnsupportedExtension,
		StatusUserActionPending:    ErrUserPresenceRequired,
		StatusNoCredentials:        ErrCredentialNotFound,
		StatusUserActionTimeout:    ErrOperationTimeout,
		StatusPINInvalid:           ErrInvalidPIN,
		StatusPINBlocked:           ErrPINBlocked,
		StatusPINAuthInvalid:       ErrPINAuthInvalid,
		StatusPINAuthBlocked:       ErrPINAuthBlocked,
		StatusPINNotSet:            ErrPINNotSet,
		StatusPINRequired:          ErrPINRequired,
		StatusUPRequired:           ErrUserPresenceRequired,
	}

	for status, want := range sentinels {
		t.Run(fmt.Sprintf("status_0x%02X", status), func(t *testing.T) {
			assert.ErrorIs(t, device.handleCTAPError(status), want)
		})
	}

	messages := map[byte]string{
		StatusInvalidCommand:     "invalid CTAP command",
		StatusInvalidParameter:   "invalid parameter",
		StatusInvalidLength:      "invalid length",
		StatusInvalidSeq:         "invalid sequence",
		StatusChannelBusy:        "channel busy",
		StatusCredentialExcluded: "credential excluded",
		StatusOperationDenied:    "operation denied",
		StatusNotAllowed:         "operation not allowed",
		StatusUVBlocked:          "user verification blocked",
	}

	for status, want := range messages {
		t.Run(fmt.Sprintf("status_0x%02X_message", status), func(t *testing.T) {
			assert.Equal(t, want, device.handleCTAPError(status).Error())
		})
	}
}
