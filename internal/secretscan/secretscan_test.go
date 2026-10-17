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

package secretscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFind_CatchesAPlantedSecretInEveryForm is the scan's self-check: a
// secret planted in a Debug record, in each form a log line could carry it,
// must be found.
func TestFind_CatchesAPlantedSecretInEveryForm(t *testing.T) {
	secret := []byte("planted-SECRET-\x01\xfe")
	plants := map[string]func(*slog.Logger){
		"string attr": func(l *slog.Logger) { l.Debug("op", slog.String("v", string(secret))) },
		"bytes attr":  func(l *slog.Logger) { l.Debug("op", slog.Any("v", secret)) },
		"hex attr":    func(l *slog.Logger) { l.Debug("op", "v", hex.EncodeToString(secret)) },
		"0x-hex message": func(l *slog.Logger) {
			l.Debug(fmt.Sprintf("secret 0x%x", secret))
		},
		"upper hex": func(l *slog.Logger) { l.Debug("op", "v", fmt.Sprintf("%X", secret)) },
		"url base64": func(l *slog.Logger) {
			l.Debug("op", "v", base64.RawURLEncoding.EncodeToString(secret))
		},
		"group attr": func(l *slog.Logger) {
			l.WithGroup("g").Debug("op", slog.String("v", string(secret)))
		},
		"logger attr": func(l *slog.Logger) {
			l.With(slog.String("v", string(secret))).Debug("op")
		},
	}
	for name, plant := range plants {
		t.Run(name, func(t *testing.T) {
			rec := NewRecorder()
			plant(slog.New(rec))
			_, found := Find(rec.Output(), secret)
			assert.True(t, found, "the scan missed a planted secret: %s", rec.Output())
		})
	}
}

// TestFind_CleanOutputAndEmptySecret covers the scan's negative answers: a
// secret that was never logged is not found, and an empty secret is never
// found, since it would match anything.
func TestFind_CleanOutputAndEmptySecret(t *testing.T) {
	rec := NewRecorder()
	logger := slog.New(rec)
	logger.Debug("op", slog.Bool("secret_set", true), slog.String("cn", "device-1"))

	_, found := Find(rec.Output(), []byte("never-logged-SECRET"))
	assert.False(t, found)

	_, found = Find(rec.Output(), nil)
	assert.False(t, found)

	RequireAbsent(t, rec.Output(), "the unlogged secret", []byte("never-logged-SECRET"))
}

// TestRecorder_KeepsDebugInTextAndJSON pins what the scan relies on: Debug
// records are kept, and each is rendered once as text and once as JSON.
func TestRecorder_KeepsDebugInTextAndJSON(t *testing.T) {
	rec := NewRecorder()
	slog.New(rec).Debug("debug-record")

	out := rec.Output()
	require.Equal(t, 2, strings.Count(out, "debug-record"))
	assert.Contains(t, out, "level=DEBUG")
	assert.Contains(t, out, `"level":"DEBUG"`)
}
