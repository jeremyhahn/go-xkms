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
