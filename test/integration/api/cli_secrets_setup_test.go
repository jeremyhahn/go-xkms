//go:build integration

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

package integration

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-xkms/test/integration/api/commands"
)

// recordingFailer records a fatal failure and stops the calling goroutine,
// as testing.T.Fatalf does, without failing the enclosing test.
type recordingFailer struct {
	fatal string
}

func (r *recordingFailer) Helper() {}

func (r *recordingFailer) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// runSetupField calls setupField on its own goroutine and reports the value it
// returned and the fatal message it raised, if any.
func runSetupField(field, out string, passed bool) (value, fatal string) {
	w := &secretsWorkflow{protocol: commands.ProtocolREST}
	f := &recordingFailer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		value = w.setupField(f, "setup-cell", field, out, passed)
	}()
	<-done
	return value, f.fatal
}

// TestSecretsSetupOutputRequired checks a producer cell that exited zero but
// printed malformed JSON, or no ID or recovery code, stops the workflow with
// a fatal failure instead of letting its dependent cells be skipped.
func TestSecretsSetupOutputRequired(t *testing.T) {
	fatalCases := []struct {
		name, field, out string
	}{
		{"malformed-json", "id", `{"id": "e1"`},
		{"not-json", "id", "entry added"},
		{"missing-id", "id", `{"name":"it-matrix"}`},
		{"empty-id", "id", `{"id":""}`},
		{"missing-recovery-code", "recoverycode", `{"id":"f1"}`},
		{"empty-recovery-code", "recoverycode", `{"id":"f1","recovery_code":""}`},
	}
	for _, tc := range fatalCases {
		value, fatal := runSetupField(tc.field, tc.out, true)
		if fatal == "" {
			t.Errorf("%s: setupField returned %q without a fatal failure", tc.name, value)
		}
	}

	if value, fatal := runSetupField("id", `{"id":"e1"}`, true); fatal != "" || value != "e1" {
		t.Errorf("valid id: value %q, fatal %q", value, fatal)
	}
	if value, fatal := runSetupField("recoverycode", `{"recovery_code":"rc"}`, true); fatal != "" || value != "rc" {
		t.Errorf("valid recovery code: fatal %q, value set %v", fatal, value != "")
	}
	// A producer cell that failed already failed its own subtest.
	if value, fatal := runSetupField("id", "", false); fatal != "" || value != "" {
		t.Errorf("failed cell: value %q, fatal %q", value, fatal)
	}
}
