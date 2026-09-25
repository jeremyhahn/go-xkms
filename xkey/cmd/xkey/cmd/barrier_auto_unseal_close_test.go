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
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFinalizeAutoUnsealStoreClose exercises finalizeAutoUnsealStoreClose in
// isolation from tryBarrierPolicyAutoUnseal, which otherwise requires the
// TPM 2.0 simulator (and, for the success path, a second independently
// provisioned simulator instance the in-process simulator cannot supply --
// see the doc comment on TestTryBarrierPolicyAutoUnseal_Success in
// barrier_auto_unseal_test.go).
func TestFinalizeAutoUnsealStoreClose(t *testing.T) {
	errUnseal := errors.New("unseal failed")
	errClose := errors.New("close failed")

	tests := []struct {
		name        string
		unsealed    bool
		err         error
		closeErr    error
		wantErr     error
		wantWrapped error
		wantLogged  bool
	}{
		{
			name:     "no close error leaves err untouched",
			unsealed: false,
			err:      errUnseal,
			closeErr: nil,
			wantErr:  errUnseal,
		},
		{
			name:     "no close error and no err stays nil",
			unsealed: true,
			err:      nil,
			closeErr: nil,
			wantErr:  nil,
		},
		{
			name:        "close error on failure path is joined",
			unsealed:    false,
			err:         errUnseal,
			closeErr:    errClose,
			wantWrapped: errClose,
		},
		{
			name:       "close error on success path is logged, not returned",
			unsealed:   true,
			err:        nil,
			closeErr:   errClose,
			wantErr:    nil,
			wantLogged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, nil))

			got := finalizeAutoUnsealStoreClose(logger, tt.unsealed, tt.err, tt.closeErr)

			if tt.wantWrapped != nil {
				assert.ErrorIs(t, got, tt.wantWrapped, "close error must be joined into the result")
				assert.ErrorIs(t, got, tt.err, "original error must still be present after joining")
			} else {
				assert.Equal(t, tt.wantErr, got)
			}

			if tt.wantLogged {
				assert.Contains(t, logBuf.String(), "failed to close PCR policy store after successful auto-unseal")
			} else {
				assert.Empty(t, logBuf.String())
			}
		})
	}
}
