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

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestBootCompletionFailure_OnlyTheBootStage pins that only the
// boot-completion stage after unseal keeps xkmsd up (#2290); every other
// New failure still exits.
func TestBootCompletionFailure_OnlyTheBootStage(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "sealed window wrapping boot completion",
			err: &QRDBNodeError{Stage: "sealed window", Err: &QRDBNodeError{
				Stage: StageBootAfterSealedWindow, Err: io.ErrUnexpectedEOF}},
			want: true,
		},
		{
			name: "sealed window wrapping a plain error",
			err:  &QRDBNodeError{Stage: "sealed window", Err: errors.New("window canceled")},
		},
		{name: "bind refusal", err: &SealedWindowBindError{}},
		{name: "nil error", err: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nodeErr, ok := BootCompletionFailure(tc.err)
			assert.Equal(t, tc.want, ok)
			if tc.want {
				require.NotNil(t, nodeErr)
				assert.Equal(t, StageBootAfterSealedWindow, nodeErr.Stage)
				assert.ErrorIs(t, nodeErr, io.ErrUnexpectedEOF)
			} else {
				assert.Nil(t, nodeErr)
			}
		})
	}
}

// TestServeBootFailure_RefusesRemoteBind pins that the failed-boot listener
// takes the sealed window's bind rule.
func TestServeBootFailure_RefusesRemoteBind(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.Host = "0.0.0.0"
	cfg.Barrier.SealedWindowAllowRemote = false
	err := ServeBootFailure(context.Background(), cfg,
		&QRDBNodeError{Stage: StageBootAfterSealedWindow, Err: io.ErrUnexpectedEOF}, slog.Default())
	var bindErr *SealedWindowBindError
	require.ErrorAs(t, err, &bindErr)
	assert.Equal(t, "0.0.0.0", bindErr.Host)
}
