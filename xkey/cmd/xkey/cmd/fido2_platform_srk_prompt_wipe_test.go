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

package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestFIDO2PlatformSRKPromptedPINIsWipedOnEveryPath is #2325: a Platform
// SRK PIN read at the terminal prompt is wiped when loadFIDO2PlatformSRKAuth
// returns, whether attach fails, VerifyAuth rejects it, or it succeeds. A
// plain `defer secure.Wipe(pin)` binds the slice before the prompt and
// leaves the prompted PIN in memory; the closure wipes the current slice.
func TestFIDO2PlatformSRKPromptedPINIsWipedOnEveryPath(t *testing.T) {
	errAttach := errors.New("attach failed")
	cases := []struct {
		name    string
		attach  func(*fakeSRKKeyStore) (xkms.PlatformKeyStorer, error)
		verify  error
		wantErr []error
		reached bool
	}{
		{
			name:    "attach-fails",
			attach:  func(*fakeSRKKeyStore) (xkms.PlatformKeyStorer, error) { return nil, errAttach },
			wantErr: []error{ErrFIDO2TPMPlatformSRKAuth, errAttach},
		},
		{
			name:    "verify-auth-rejected",
			attach:  func(f *fakeSRKKeyStore) (xkms.PlatformKeyStorer, error) { return f, nil },
			verify:  fmt.Errorf("%w: TPM_RC_AUTH_FAIL", xkms.ErrTPMAuthFailed),
			wantErr: []error{ErrFIDO2TPMPlatformSRKAuth, ErrFIDO2TPMPlatformSRKAuthRejected},
			reached: true,
		},
		{
			name:    "success",
			attach:  func(f *fakeSRKKeyStore) (xkms.PlatformKeyStorer, error) { return f, nil },
			reached: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(pinEnvVar, "")
			prevTerminal, prevPrompt := pinInputIsTerminal, promptFIDO2PlatformSRKPIN
			t.Cleanup(func() { pinInputIsTerminal, promptFIDO2PlatformSRKPIN = prevTerminal, prevPrompt })
			prompted := []byte(testFollowupPIN)
			pinInputIsTerminal = func() bool { return true }
			promptFIDO2PlatformSRKPIN = func() ([]byte, error) { return prompted, nil }

			pks := &fakeSRKKeyStore{verifyErr: tc.verify}
			err := loadFIDO2PlatformSRKAuth(&FIDO2Config{}, func() (xkms.PlatformKeyStorer, error) { return tc.attach(pks) })
			if len(tc.wantErr) == 0 {
				require.NoError(t, err)
			}
			for _, want := range tc.wantErr {
				require.ErrorIs(t, err, want)
			}
			if err != nil {
				assert.NotContains(t, err.Error(), testFollowupPIN, "the PIN never appears in an error")
			}
			assert.Equal(t, tc.reached, pks.verified == testFollowupPIN, "the prompted PIN reaches VerifyAuth only after attach")
			assert.True(t, isZeroed(prompted), "the prompted PIN is wiped")
		})
	}
}

// isZeroed reports whether every byte of b is zero; the assertion message
// carries no PIN bytes.
func isZeroed(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}
