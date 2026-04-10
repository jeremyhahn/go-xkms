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

package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// resetTouchFlags resets all touch command flags to their default values.
// This is necessary because Cobra retains flag state across RootCmd.Execute()
// calls within the same process, which causes test pollution.
func resetTouchFlags() {
	cmds := []*pflag.FlagSet{
		touchCmd.Flags(),
		passwordTypeCmd.Flags(),
	}
	for _, fs := range cmds {
		fs.VisitAll(func(f *pflag.Flag) {
			f.Changed = false
			_ = f.Value.Set(f.DefValue)
		})
	}
}

func TestTouchCmd_Help(t *testing.T) {
	resetTouchFlags()
	resetPasswordFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"touch", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("touch --help failed: %v", err)
	}

	output := buf.String()
	expected := []string{
		"touch",
		"--password",
		"--socket",
		"WebAuthn",
		"daemon",
	}
	for _, s := range expected {
		if !strings.Contains(output, s) {
			t.Errorf("touch help missing %q", s)
		}
	}
}

func TestTouchCmd_IsRegistered(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Use == "touch" {
			found = true
			break
		}
	}
	if !found {
		t.Error("touch command not registered with root")
	}
}

func TestPasswordTypeCmd_Help(t *testing.T) {
	resetTouchFlags()
	resetPasswordFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "type", "--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("password type --help failed: %v", err)
	}

	output := buf.String()
	expected := []string{
		"type",
		"--socket",
		"keyboard",
		"daemon",
	}
	for _, s := range expected {
		if !strings.Contains(output, s) {
			t.Errorf("password type help missing %q", s)
		}
	}
}

func TestPasswordTypeCmd_IsRegistered(t *testing.T) {
	found := false
	for _, cmd := range PasswordCmd.Commands() {
		if cmd.Use == "type [name]" {
			found = true
			break
		}
	}
	if !found {
		t.Error("type subcommand not registered with password")
	}
}

func TestPasswordTypeCmd_MissingArg(t *testing.T) {
	resetTouchFlags()
	resetPasswordFlags()

	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"password", "type"})

	err := RootCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing type arg")
	}
	if err != ErrPasswordMissingTypeArg {
		t.Errorf("expected ErrPasswordMissingTypeArg, got: %v", err)
	}
}

// TestTouchCmd_Errors verifies that touch command sentinel errors have the
// expected messages.
func TestTouchCmd_Errors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrTouchDaemonNotRunning", ErrTouchDaemonNotRunning, "touch: daemon is not running"},
		{"ErrTouchFailed", ErrTouchFailed, "touch: operation failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.want) {
				t.Errorf("error %q missing %q", tt.err.Error(), tt.want)
			}
		})
	}
}

// TestPasswordTypeCmdErrors verifies that password type command sentinel errors
// have the expected messages.
func TestPasswordTypeCmdErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrPasswordTypeFailed", ErrPasswordTypeFailed, "password: type operation failed"},
		{"ErrPasswordMissingTypeArg", ErrPasswordMissingTypeArg, "password: specify password name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.err.Error(), tt.want) {
				t.Errorf("error %q missing %q", tt.err.Error(), tt.want)
			}
		})
	}
}
