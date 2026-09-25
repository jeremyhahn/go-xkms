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
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// invocation matches an `xkey ...` command line in the skill, up to the
// end of the line or a shell operator that ends the command.
var invocation = regexp.MustCompile(`\bxkey((?:\s+[^\s|;&>` + "`" + `)]+)+)`)

// flagToken matches a long flag name inside an invocation.
var flagToken = regexp.MustCompile(`^--([a-z0-9][a-z0-9-]*)`)

// checkSkill reads the skill at path and reports every `xkey` invocation
// whose command path or long flag does not exist in root's command tree.
func checkSkill(path string, root *cobra.Command) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var problems []string
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		for _, m := range invocation.FindAllStringSubmatch(sc.Text(), -1) {
			if p := checkInvocation(root, strings.Fields(m[1])); p != "" {
				problems = append(problems, fmt.Sprintf("%s:%d: %s", path, n, p))
			}
		}
	}
	return problems, sc.Err()
}

// checkInvocation resolves args against root's subcommands and verifies each
// long flag that follows is defined on the resolved command or inherited.
// It returns a description of the first problem, or "".
func checkInvocation(root *cobra.Command, args []string) string {
	c := root
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") || strings.ContainsAny(a, "<[{$=\"'/.") {
			break
		}
		next := findSub(c, a)
		if next == nil {
			// A positional argument ends the command path, but only once
			// the path resolves to a runnable command.
			if !c.Runnable() {
				return fmt.Sprintf("unknown command %q under %q", a, c.CommandPath())
			}
			break
		}
		c = next
	}
	if c == root {
		return ""
	}
	for ; i < len(args); i++ {
		m := flagToken.FindStringSubmatch(args[i])
		if m == nil {
			continue
		}
		if c.Flags().Lookup(m[1]) == nil && c.InheritedFlags().Lookup(m[1]) == nil {
			return fmt.Sprintf("unknown flag --%s for %q", m[1], c.CommandPath())
		}
	}
	return ""
}

// findSub returns c's subcommand named or aliased name, or nil.
func findSub(c *cobra.Command, name string) *cobra.Command {
	for _, sub := range c.Commands() {
		if sub.Name() == name || sub.HasAlias(name) {
			return sub
		}
	}
	return nil
}
