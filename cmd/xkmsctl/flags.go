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
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// FlagReadError reports that a flag registered on a cobra command could not
// be read with the requested pflag type. It only occurs when a flag name
// was misspelled, or a flag was read with a type that does not match how
// it was registered — both programmer errors. TestFlagBindings (in
// flags_test.go) walks every command in the tree and every flag it reads,
// so a mistake here is caught in CI rather than at the moment an operator
// happens to hit the affected verb.
type FlagReadError struct {
	Command string
	Flag    string
	Kind    string
	Cause   error
}

// Error returns a human-readable description.
func (e *FlagReadError) Error() string {
	return fmt.Sprintf("xkmsctl: %s: --%s (%s): %v", e.Command, e.Flag, e.Kind, e.Cause)
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *FlagReadError) Unwrap() error { return e.Cause }

// flagReader reads a command's flags, recording the first read error
// instead of returning it from every call. A single command commonly reads
// several flags per invocation; checking each one individually would
// multiply every handler by the number of flags it reads. Recording the
// first error and checking it once, after the whole block of reads, gives
// every read site the same safety with one check per command instead of
// one per flag — the same shape as outputWriter for command output.
type flagReader struct {
	cmd *cobra.Command
	err error
}

// newFlagReader returns a flagReader bound to cmd.
func newFlagReader(cmd *cobra.Command) *flagReader {
	return &flagReader{cmd: cmd}
}

// Err returns the first flag-read error recorded, if any.
func (r *flagReader) Err() error {
	return r.err
}

// String reads the string flag name. It returns the zero value once an
// earlier read on this reader has failed.
func (r *flagReader) String(name string) string {
	if r.err != nil {
		return ""
	}
	v, err := r.cmd.Flags().GetString(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "string", Cause: err}
		return ""
	}
	return v
}

// Bool reads the bool flag name. It returns the zero value once an earlier
// read on this reader has failed.
func (r *flagReader) Bool(name string) bool {
	if r.err != nil {
		return false
	}
	v, err := r.cmd.Flags().GetBool(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "bool", Cause: err}
		return false
	}
	return v
}

// Int reads the int flag name. It returns the zero value once an earlier
// read on this reader has failed.
func (r *flagReader) Int(name string) int {
	if r.err != nil {
		return 0
	}
	v, err := r.cmd.Flags().GetInt(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "int", Cause: err}
		return 0
	}
	return v
}

// Int64 reads the int64 flag name. It returns the zero value once an
// earlier read on this reader has failed.
func (r *flagReader) Int64(name string) int64 {
	if r.err != nil {
		return 0
	}
	v, err := r.cmd.Flags().GetInt64(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "int64", Cause: err}
		return 0
	}
	return v
}

// Uint reads the uint flag name. It returns the zero value once an earlier
// read on this reader has failed.
func (r *flagReader) Uint(name string) uint {
	if r.err != nil {
		return 0
	}
	v, err := r.cmd.Flags().GetUint(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "uint", Cause: err}
		return 0
	}
	return v
}

// Uint32 reads the uint32 flag name. It returns the zero value once an
// earlier read on this reader has failed.
func (r *flagReader) Uint32(name string) uint32 {
	if r.err != nil {
		return 0
	}
	v, err := r.cmd.Flags().GetUint32(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "uint32", Cause: err}
		return 0
	}
	return v
}

// Duration reads the duration flag name. It returns the zero value once an
// earlier read on this reader has failed.
func (r *flagReader) Duration(name string) time.Duration {
	if r.err != nil {
		return 0
	}
	v, err := r.cmd.Flags().GetDuration(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "duration", Cause: err}
		return 0
	}
	return v
}

// StringSlice reads the []string flag name. It returns nil once an earlier
// read on this reader has failed.
func (r *flagReader) StringSlice(name string) []string {
	if r.err != nil {
		return nil
	}
	v, err := r.cmd.Flags().GetStringSlice(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "stringSlice", Cause: err}
		return nil
	}
	return v
}

// IntSlice reads the []int flag name. It returns nil once an earlier read
// on this reader has failed.
func (r *flagReader) IntSlice(name string) []int {
	if r.err != nil {
		return nil
	}
	v, err := r.cmd.Flags().GetIntSlice(name)
	if err != nil {
		r.err = &FlagReadError{Command: r.cmd.CommandPath(), Flag: name, Kind: "intSlice", Cause: err}
		return nil
	}
	return v
}

// ---------------------------------------------------------------------------
// Command-tree construction errors
// ---------------------------------------------------------------------------

// InitError reports that building the cobra command tree failed — for
// example, cmd.MarkFlagRequired named a flag that was never registered on
// cmd. It is always a programmer error: TestInitErrors (flags_test.go)
// asserts initErrors is empty, so a mistake here fails CI on every build
// instead of surfacing only when an operator reaches the affected command.
type InitError struct {
	Command string
	Detail  string
	Cause   error
}

// Error returns a human-readable description.
func (e *InitError) Error() string {
	return fmt.Sprintf("xkmsctl: %s: %s: %v", e.Command, e.Detail, e.Cause)
}

// Unwrap returns the wrapped cause for errors.Is/As.
func (e *InitError) Unwrap() error { return e.Cause }

// initErrors accumulates errors raised while building the command tree in
// package init() functions. init() runs single-threaded before main, so no
// synchronization is needed. Execute checks it before running any command;
// TestInitErrors asserts it is empty.
var initErrors []error

// markFlagRequired marks name required on cmd, recording any error in
// initErrors instead of discarding it. It exists so every command-tree
// MarkFlagRequired call records a failure instead of silently building a
// command tree with an unenforced required flag.
func markFlagRequired(cmd *cobra.Command, name string) {
	if err := cmd.MarkFlagRequired(name); err != nil {
		initErrors = append(initErrors, &InitError{
			Command: cmd.CommandPath(),
			Detail:  "mark --" + name + " required",
			Cause:   err,
		})
	}
}
