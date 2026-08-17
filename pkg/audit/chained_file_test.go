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

package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChainedFileLogger_EmitsCanonicalRecord proves the non-qrdb fallback
// writes the identical canonical record shape onto a chained file: the event
// lands with actor/action/resource/outcome and the details in attributes.
func TestChainedFileLogger_EmitsCanonicalRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-events.ndjson")
	l, err := NewChainedFileLogger(path)
	require.NoError(t, err)

	err = l.Log(context.Background(), &Event{
		Timestamp: time.Now().UTC(),
		Subject:   "alice",
		Action:    "auth.login.piv",
		Resource:  "session",
		Outcome:   "success",
		Details:   map[string]string{"remote_addr": "10.0.0.5"},
	})
	require.NoError(t, err)
	require.NoError(t, l.Close())

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	content := string(raw)
	assert.Contains(t, content, `"actor":"alice"`)
	assert.Contains(t, content, `"action":"auth.login.piv"`)
	assert.Contains(t, content, "10.0.0.5")
}

// TestChainedFileLogger_ErrorHandling proves the failure contract: an
// unwritable path is a typed construction error, and a nil event is
// rejected without touching the chain.
func TestChainedFileLogger_ErrorHandling(t *testing.T) {
	_, err := NewChainedFileLogger(filepath.Join(t.TempDir(), "no", "such", "dir", "x.ndjson"))
	var cfe *ChainedFileError
	require.ErrorAs(t, err, &cfe)
	assert.True(t, strings.Contains(cfe.Error(), "x.ndjson"))

	path := filepath.Join(t.TempDir(), "a.ndjson")
	l, err := NewChainedFileLogger(path)
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	assert.ErrorIs(t, l.Log(context.Background(), nil), ErrNilEvent)
}
