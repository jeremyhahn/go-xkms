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

// Command skillgen writes the complete xkey CLI reference used by the
// xkey-agent skill. It walks the live cobra command tree, so the reference
// can never describe a command or flag that does not exist.
//
// Usage: go run -tags 'ble codec_json' ./tools/skillgen > skills/xkey-agent/reference/cli.md
package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd"
)

func main() {
	if err := run(os.Args[1:], cmd.RootCmd, os.Stdout); err != nil {
		fail(err)
	}
}

// problemsError lists the skill invocations the command tree does not know.
type problemsError struct{ problems []string }

func (e *problemsError) Error() string { return strings.Join(e.problems, "\n") }

// run checks the skill named by "-check <path>" against root, or otherwise
// writes the reference for root to out.
func run(args []string, root *cobra.Command, out io.Writer) error {
	if len(args) == 2 && args[0] == "-check" {
		problems, err := checkSkill(args[1], root)
		if err != nil {
			return err
		}
		if len(problems) > 0 {
			return &problemsError{problems: problems}
		}
		return nil
	}
	bw := bufio.NewWriter(out)
	w := &writer{w: bw}
	render(w, root)
	if w.err != nil {
		return w.err
	}
	return bw.Flush()
}

// fail reports err on stderr and exits non-zero. A failed write to stderr
// cannot be reported anywhere, so the exit status carries the failure.
func fail(err error) {
	if _, werr := fmt.Fprintln(os.Stderr, "skillgen:", err); werr != nil {
		os.Exit(2)
	}
	os.Exit(1)
}

// writer records the first write error and turns every later write into a
// no-op, so render can write freely and main checks one error at the end.
type writer struct {
	w   *bufio.Writer
	err error
}

func (w *writer) printf(format string, a ...any) {
	if w.err == nil {
		_, w.err = fmt.Fprintf(w.w, format, a...)
	}
}

func (w *writer) println(a ...any) {
	if w.err == nil {
		_, w.err = fmt.Fprintln(w.w, a...)
	}
}

// render writes the reference header and every visible command below root.
func render(w *writer, root *cobra.Command) {
	w.println("# xkey CLI reference")
	w.println()
	w.println("Generated from the xkey cobra command tree by `make skill-reference`; do not edit by hand.")
	w.println()
	w.println("## Global flags")
	w.println()
	writeFlags(w, root.PersistentFlags())
	walk(w, root)
}

// walk writes each visible subcommand of c, sorted by name, depth first.
func walk(w *writer, c *cobra.Command) {
	for _, child := range visible(c.Commands()) {
		w.printf("## %s\n\n", child.CommandPath())
		if child.Short != "" {
			w.printf("%s\n\n", strings.TrimSpace(child.Short))
		}
		w.printf("Usage: `%s`\n\n", child.UseLine())
		if len(child.Aliases) > 0 {
			w.printf("Aliases: %s\n\n", strings.Join(child.Aliases, ", "))
		}
		writeFlags(w, child.LocalNonPersistentFlags())
		if pf := child.PersistentFlags(); pf.HasAvailableFlags() {
			w.println("Inherited by subcommands:")
			w.println()
			writeFlags(w, pf)
		}
		walk(w, child)
	}
}

// visible returns the non-hidden, available commands sorted by name,
// excluding cobra's generated help and completion commands.
func visible(cmds []*cobra.Command) []*cobra.Command {
	out := make([]*cobra.Command, 0, len(cmds))
	for _, c := range cmds {
		if c.Hidden || !c.IsAvailableCommand() || c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// writeFlags writes fs's visible flags as a table sorted by name, or nothing
// when fs has none.
func writeFlags(w *writer, fs *pflag.FlagSet) {
	var flags []*pflag.Flag
	fs.VisitAll(func(f *pflag.Flag) {
		if !f.Hidden && f.Name != "help" {
			flags = append(flags, f)
		}
	})
	if len(flags) == 0 {
		return
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	w.println("| Flag | Type | Default | Description |")
	w.println("|---|---|---|---|")
	for _, f := range flags {
		name := "`--" + f.Name + "`"
		if f.Shorthand != "" {
			name += ", `-" + f.Shorthand + "`"
		}
		w.printf("| %s | %s | %s | %s |\n", name, f.Value.Type(), cell(f.DefValue), cell(f.Usage))
	}
	w.println()
}

// cell escapes s for a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}
