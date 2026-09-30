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

package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// newFlagReaderTestCmd returns a *cobra.Command with one flag of every
// kind flagReader supports registered under its canonical name.
func newFlagReaderTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().String("s", "sval", "")
	cmd.Flags().Bool("b", true, "")
	cmd.Flags().Int("i", 7, "")
	cmd.Flags().Int64("i64", 64, "")
	cmd.Flags().Uint("u", 8, "")
	cmd.Flags().Uint32("u32", 32, "")
	cmd.Flags().Duration("d", 5*time.Second, "")
	cmd.Flags().StringSlice("ss", []string{"a", "b"}, "")
	cmd.Flags().IntSlice("is", []int{1, 2}, "")
	cmd.Flags().StringArray("sa", []string{"a,b"}, "")
	return cmd
}

func TestFlagReader_Success(t *testing.T) {
	cmd := newFlagReaderTestCmd()
	fr := newFlagReader(cmd)

	if got := fr.String("s"); got != "sval" {
		t.Errorf("String: got %q, want %q", got, "sval")
	}
	if got := fr.Bool("b"); got != true {
		t.Errorf("Bool: got %v, want true", got)
	}
	if got := fr.Int("i"); got != 7 {
		t.Errorf("Int: got %d, want 7", got)
	}
	if got := fr.Int64("i64"); got != 64 {
		t.Errorf("Int64: got %d, want 64", got)
	}
	if got := fr.Uint("u"); got != 8 {
		t.Errorf("Uint: got %d, want 8", got)
	}
	if got := fr.Uint32("u32"); got != 32 {
		t.Errorf("Uint32: got %d, want 32", got)
	}
	if got := fr.Duration("d"); got != 5*time.Second {
		t.Errorf("Duration: got %v, want 5s", got)
	}
	if got := fr.StringSlice("ss"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("StringSlice: got %v, want [a b]", got)
	}
	if got := fr.IntSlice("is"); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("IntSlice: got %v, want [1 2]", got)
	}
	if got := fr.StringArray("sa"); len(got) != 1 || got[0] != "a,b" {
		t.Errorf("StringArray: got %v, want [a,b] whole", got)
	}
	if err := fr.Err(); err != nil {
		t.Fatalf("Err: got %v, want nil", err)
	}
}

func TestFlagReader_UnknownFlagRecordsTypedError(t *testing.T) {
	tests := []struct {
		name string
		read func(*flagReader) any
		kind string
	}{
		{"String", func(r *flagReader) any { return r.String("missing") }, "string"},
		{"Bool", func(r *flagReader) any { return r.Bool("missing") }, "bool"},
		{"Int", func(r *flagReader) any { return r.Int("missing") }, "int"},
		{"Int64", func(r *flagReader) any { return r.Int64("missing") }, "int64"},
		{"Uint", func(r *flagReader) any { return r.Uint("missing") }, "uint"},
		{"Uint32", func(r *flagReader) any { return r.Uint32("missing") }, "uint32"},
		{"Duration", func(r *flagReader) any { return r.Duration("missing") }, "duration"},
		{"StringSlice", func(r *flagReader) any { return r.StringSlice("missing") }, "stringSlice"},
		{"IntSlice", func(r *flagReader) any { return r.IntSlice("missing") }, "intSlice"},
		{"StringArray", func(r *flagReader) any { return r.StringArray("missing") }, "stringArray"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := &cobra.Command{Use: "x"}
			fr := newFlagReader(cmd)
			tt.read(fr)

			err := fr.Err()
			if err == nil {
				t.Fatal("Err: got nil, want a FlagReadError")
			}
			var fre *FlagReadError
			if !errors.As(err, &fre) {
				t.Fatalf("Err: got %T, want *FlagReadError", err)
			}
			if fre.Flag != "missing" {
				t.Errorf("Flag: got %q, want %q", fre.Flag, "missing")
			}
			if fre.Kind != tt.kind {
				t.Errorf("Kind: got %q, want %q", fre.Kind, tt.kind)
			}
			if fre.Command != "x" {
				t.Errorf("Command: got %q, want %q", fre.Command, "x")
			}
			if fre.Unwrap() == nil {
				t.Error("Unwrap: got nil, want the underlying pflag error")
			}
		})
	}
}

// TestFlagReader_ErrShortCircuits confirms a flagReader stops touching the
// flag set and keeps returning zero values once it has recorded an error,
// so a command reading several flags in a row gets exactly one error even
// when more than one of them is missing.
func TestFlagReader_ErrShortCircuits(t *testing.T) {
	cmd := newFlagReaderTestCmd()
	fr := newFlagReader(cmd)

	fr.String("also-missing")
	first := fr.Err()
	if first == nil {
		t.Fatal("Err: got nil after a missing flag read")
	}

	if got := fr.String("s"); got != "" {
		t.Errorf("String after error: got %q, want zero value", got)
	}
	if got := fr.Int("i"); got != 0 {
		t.Errorf("Int after error: got %d, want zero value", got)
	}
	if got := fr.Bool("b"); got != false {
		t.Errorf("Bool after error: got %v, want zero value", got)
	}
	fr.Bool("another-missing")
	if fr.Err() != first {
		t.Error("Err: a later read overwrote the first recorded error")
	}
}

func TestFlagReadError_Error(t *testing.T) {
	cause := errors.New("boom")
	err := &FlagReadError{Command: "key generate", Flag: "key-type", Kind: "string", Cause: cause}
	got := err.Error()
	for _, want := range []string{"key generate", "key-type", "string", "boom"} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to contain %q", got, want)
		}
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is: err does not unwrap to cause")
	}
}

// --- markFlagRequired / initErrors -----------------------------------------

// withCleanInitErrors saves and clears the package-level initErrors slice
// for the duration of the test, so a test that intentionally records a
// bogus entry cannot leak it into TestInitErrors or any other test that
// inspects initErrors.
func withCleanInitErrors(t *testing.T) {
	t.Helper()
	saved := initErrors
	initErrors = nil
	t.Cleanup(func() { initErrors = saved })
}

func TestMarkFlagRequired_Success(t *testing.T) {
	withCleanInitErrors(t)
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().String("name", "", "")

	markFlagRequired(cmd, "name")

	if len(initErrors) != 0 {
		t.Fatalf("initErrors: got %v, want empty", initErrors)
	}
}

func TestMarkFlagRequired_UnknownFlagRecordsInitError(t *testing.T) {
	withCleanInitErrors(t)
	cmd := &cobra.Command{Use: "x"}

	markFlagRequired(cmd, "does-not-exist")

	if len(initErrors) != 1 {
		t.Fatalf("initErrors: got %d entries, want 1", len(initErrors))
	}
	var ie *InitError
	if !errors.As(initErrors[0], &ie) {
		t.Fatalf("initErrors[0]: got %T, want *InitError", initErrors[0])
	}
	if ie.Command != "x" {
		t.Errorf("Command: got %q, want %q", ie.Command, "x")
	}
	if ie.Unwrap() == nil {
		t.Error("Unwrap: got nil, want the underlying cobra error")
	}
}

func TestExecute_FailsFastOnInitErrors(t *testing.T) {
	withCleanInitErrors(t)
	initErrors = append(initErrors, &InitError{Command: "x", Detail: "test", Cause: errors.New("boom")})

	err := Execute()
	if err == nil {
		t.Fatal("Execute: got nil error with a non-empty initErrors")
	}
}
