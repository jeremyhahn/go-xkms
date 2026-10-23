package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// testTree is a small command tree with every shape render and the checker
// distinguish: a hidden command, aliases, local, persistent, hidden and
// shorthand flags, and a usage string that needs escaping.
func testTree() *cobra.Command {
	run := func(*cobra.Command, []string) {}
	root := &cobra.Command{Use: "xkey"}
	root.PersistentFlags().String("server", "", "server `address`")

	keys := &cobra.Command{Use: "keys", Short: "  Manage keys  ", Aliases: []string{"key", "k"}}
	keys.PersistentFlags().Bool("json", false, "print JSON")

	sign := &cobra.Command{Use: "sign <key-id>", Short: "Sign data", Run: run}
	sign.Flags().StringP("algorithm", "a", "ES256", "signature algorithm | name\nsecond line")
	sign.Flags().String("secret-debug", "", "hidden flag")
	if err := sign.Flags().MarkHidden("secret-debug"); err != nil {
		panic(err)
	}
	list := &cobra.Command{Use: "list", Run: run}
	keys.AddCommand(sign, list)

	hidden := &cobra.Command{Use: "internal", Hidden: true, Run: run}
	version := &cobra.Command{Use: "version", Short: "Print the version", Run: run}
	root.AddCommand(version, keys, hidden)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	return root
}

func renderTree(t *testing.T, root *cobra.Command) string {
	t.Helper()
	var out bytes.Buffer
	w := &writer{w: bufio.NewWriter(&out)}
	render(w, root)
	if w.err != nil {
		t.Fatalf("render: %v", w.err)
	}
	if err := w.w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return out.String()
}

func TestRender_WritesEveryVisibleCommandInOrder(t *testing.T) {
	out := renderTree(t, testTree())

	for _, want := range []string{
		"# xkey CLI reference\n",
		"## Global flags\n\n| Flag | Type | Default | Description |\n|---|---|---|---|\n| `--server` | string |  | server `address` |\n",
		"## xkey keys\n\nManage keys\n\nUsage: `xkey keys`\n\nAliases: key, k\n\n",
		"Inherited by subcommands:\n\n| Flag | Type | Default | Description |\n|---|---|---|---|\n| `--json` | bool | false | print JSON |\n",
		"## xkey keys sign\n\nSign data\n\nUsage: `xkey keys sign <key-id> [flags]`\n\n",
		"| `--algorithm`, `-a` | string | ES256 | signature algorithm \\| name second line |\n",
		"## xkey version\n\nPrint the version\n\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("reference lacks %q:\n%s", want, out)
		}
	}
	keys, list, version := strings.Index(out, "## xkey keys\n"), strings.Index(out, "## xkey keys list\n"), strings.Index(out, "## xkey version\n")
	if keys > list || list > version {
		t.Fatalf("commands are not depth-first in name order: keys=%d list=%d version=%d", keys, list, version)
	}
}

func TestRender_OmitsHiddenHelpAndCompletion(t *testing.T) {
	out := renderTree(t, testTree())

	for _, absent := range []string{"xkey internal", "xkey help", "xkey completion", "secret-debug", "`--help`"} {
		if strings.Contains(out, absent) {
			t.Fatalf("reference contains %q:\n%s", absent, out)
		}
	}
	if strings.Contains(out, "## xkey keys list\n\n\n") {
		t.Fatalf("a command without a short description left an empty paragraph:\n%s", out)
	}
}

func TestWriteFlags_WritesNothingForAnEmptySet(t *testing.T) {
	var out bytes.Buffer
	w := &writer{w: bufio.NewWriter(&out)}

	writeFlags(w, (&cobra.Command{Use: "bare"}).LocalNonPersistentFlags())

	if err := w.w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("empty flag set wrote %q", out.String())
	}
}

func TestCell_EscapesTableBreakingCharacters(t *testing.T) {
	if got := cell("a|b\nc"); got != `a\|b c` {
		t.Fatalf("cell = %q, want %q", got, `a\|b c`)
	}
	if got := cell("plain"); got != "plain" {
		t.Fatalf("cell = %q, want it unchanged", got)
	}
}

// failingWriter fails every write, as a closed stdout does.
type failingWriter struct{ writes int }

var errFailingWriter = errors.New("write failed")

func (f *failingWriter) Write([]byte) (int, error) {
	f.writes++
	return 0, errFailingWriter
}

func TestWriter_LatchesTheFirstError(t *testing.T) {
	dst := &failingWriter{}
	// A zero-size buffer is raised to the minimum, so a write larger than
	// that reaches dst at once.
	w := &writer{w: bufio.NewWriterSize(dst, 16)}

	w.printf("%s", strings.Repeat("x", 64))
	w.println(strings.Repeat("y", 64))
	w.printf("%s", "z")

	if !errors.Is(w.err, errFailingWriter) {
		t.Fatalf("writer error = %v, want the first write error", w.err)
	}
	if dst.writes != 1 {
		t.Fatalf("destination saw %d writes after the error, want 1", dst.writes)
	}
}

func writeSkill(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write skill: %v", err)
	}
	return path
}

func TestCheckSkill_AcceptsValidInvocations(t *testing.T) {
	path := writeSkill(t, strings.Join([]string{
		"Run `xkey keys sign my-key --algorithm ES256 --json --server host:1` to sign.",
		"Aliases work: xkey k list --json | jq .",
		"A placeholder ends the path: xkey keys sign <key-id> --algorithm=ES256",
		"Global flags alone are not checked: `xkey --server x`.",
		"xkey version",
	}, "\n"))

	problems, err := checkSkill(path, testTree())
	if err != nil {
		t.Fatalf("checkSkill: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("valid skill reported problems: %v", problems)
	}
}

func TestCheckSkill_ReportsUnknownCommandsAndFlags(t *testing.T) {
	path := writeSkill(t, strings.Join([]string{
		"intro",
		"xkey keys rotate my-key",
		"xkey keys sign my-key --curve P-256",
		"xkey bogus",
	}, "\n"))

	problems, err := checkSkill(path, testTree())
	if err != nil {
		t.Fatalf("checkSkill: %v", err)
	}
	want := []string{
		path + `:2: unknown command "rotate" under "xkey keys"`,
		path + `:3: unknown flag --curve for "xkey keys sign"`,
		path + `:4: unknown command "bogus" under "xkey"`,
	}
	if strings.Join(problems, "\n") != strings.Join(want, "\n") {
		t.Fatalf("problems =\n%s\nwant\n%s", strings.Join(problems, "\n"), strings.Join(want, "\n"))
	}
}

func TestCheckSkill_FailsOnAMissingFile(t *testing.T) {
	problems, err := checkSkill(filepath.Join(t.TempDir(), "absent.md"), testTree())

	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("checkSkill error = %v, want os.ErrNotExist", err)
	}
	if problems != nil {
		t.Fatalf("problems = %v, want none", problems)
	}
}

func TestCheckSkill_FailsOnAnOverlongLine(t *testing.T) {
	path := writeSkill(t, strings.Repeat("x", bufio.MaxScanTokenSize+1))

	if _, err := checkSkill(path, testTree()); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("checkSkill error = %v, want bufio.ErrTooLong", err)
	}
}

func TestFindSub_MatchesNamesAndAliases(t *testing.T) {
	root := testTree()

	for _, name := range []string{"keys", "key", "k"} {
		if got := findSub(root, name); got == nil || got.Name() != "keys" {
			t.Fatalf("findSub(%q) = %v, want keys", name, got)
		}
	}
	if got := findSub(root, "nope"); got != nil {
		t.Fatalf("findSub(nope) = %q, want nil", got.Name())
	}
}

func TestRun_WritesTheReference(t *testing.T) {
	var out bytes.Buffer

	if err := run(nil, testTree(), &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.HasPrefix(out.String(), "# xkey CLI reference\n") || !strings.Contains(out.String(), "## xkey keys sign\n") {
		t.Fatalf("run wrote an incomplete reference:\n%s", out.String())
	}
}

func TestRun_FailsWhenTheReferenceCannotBeWritten(t *testing.T) {
	if err := run(nil, testTree(), &failingWriter{}); !errors.Is(err, errFailingWriter) {
		t.Fatalf("run error = %v, want the write error", err)
	}
}

func TestRun_FailsWhenTheFlushFails(t *testing.T) {
	// A tree too small to fill the buffer fails only at the final flush.
	if err := run(nil, &cobra.Command{Use: "xkey"}, &failingWriter{}); !errors.Is(err, errFailingWriter) {
		t.Fatalf("run error = %v, want the flush error", err)
	}
}

func TestRun_ChecksASkill(t *testing.T) {
	valid := writeSkill(t, "xkey keys list --json\n")
	if err := run([]string{"-check", valid}, testTree(), &failingWriter{}); err != nil {
		t.Fatalf("run -check on a valid skill: %v", err)
	}

	invalid := writeSkill(t, "xkey keys rotate\nxkey keys sign k --curve P-256\n")
	err := run([]string{"-check", invalid}, testTree(), &failingWriter{})
	var problems *problemsError
	if !errors.As(err, &problems) || len(problems.problems) != 2 {
		t.Fatalf("run -check error = %v, want both problems", err)
	}
	if !strings.Contains(err.Error(), ":1: unknown command") || !strings.Contains(err.Error(), "\n"+invalid+":2: unknown flag") {
		t.Fatalf("problems error = %q, want one line per problem", err.Error())
	}

	missing := filepath.Join(t.TempDir(), "absent.md")
	if err := run([]string{"-check", missing}, testTree(), &failingWriter{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("run -check on a missing skill = %v, want os.ErrNotExist", err)
	}
}

// goldenTree is a command tree whose whole reference is pinned below: an
// aliased group with an inherited flag, a command whose local flags must
// come out in name order with the hidden one left out, and a hidden command.
func goldenTree(t *testing.T) *cobra.Command {
	t.Helper()
	run := func(*cobra.Command, []string) {}
	root := &cobra.Command{Use: "xkey"}
	root.PersistentFlags().StringP("config", "c", "", "config file")

	key := &cobra.Command{Use: "key", Short: "Manage keys", Aliases: []string{"keys", "k"}}
	key.PersistentFlags().String("backend", "pkcs11", "key backend")

	gen := &cobra.Command{Use: "gen <name>", Short: "  Generate a key  ", Run: run}
	gen.Flags().String("type", "ecdsa", "rsa | ecdsa")
	gen.Flags().IntP("bits", "b", 256, "key\nsize")
	gen.Flags().Bool("debug", false, "debug output")
	if err := gen.Flags().MarkHidden("debug"); err != nil {
		t.Fatal(err)
	}

	secret := &cobra.Command{Use: "secret", Hidden: true, Run: run}
	alpha := &cobra.Command{Use: "alpha", Run: run}

	key.AddCommand(gen, secret)
	root.AddCommand(key, alpha)
	return root
}

// goldenReference is the exact reference goldenTree renders. Pinning every
// byte catches what the fragment checks above cannot: the generated-file
// header, the blank lines between sections and the order of a command's flags.
const goldenReference = "# xkey CLI reference\n" +
	"\n" +
	"Generated from the xkey cobra command tree by `make skill-reference`; do not edit by hand.\n" +
	"\n" +
	"## Global flags\n" +
	"\n" +
	"| Flag | Type | Default | Description |\n" +
	"|---|---|---|---|\n" +
	"| `--config`, `-c` | string |  | config file |\n" +
	"\n" +
	"## xkey alpha\n" +
	"\n" +
	"Usage: `xkey alpha`\n" +
	"\n" +
	"## xkey key\n" +
	"\n" +
	"Manage keys\n" +
	"\n" +
	"Usage: `xkey key`\n" +
	"\n" +
	"Aliases: keys, k\n" +
	"\n" +
	"Inherited by subcommands:\n" +
	"\n" +
	"| Flag | Type | Default | Description |\n" +
	"|---|---|---|---|\n" +
	"| `--backend` | string | pkcs11 | key backend |\n" +
	"\n" +
	"## xkey key gen\n" +
	"\n" +
	"Generate a key\n" +
	"\n" +
	"Usage: `xkey key gen <name> [flags]`\n" +
	"\n" +
	"| Flag | Type | Default | Description |\n" +
	"|---|---|---|---|\n" +
	"| `--bits`, `-b` | int | 256 | key size |\n" +
	"| `--type` | string | ecdsa | rsa \\| ecdsa |\n" +
	"\n"

func TestRun_WritesTheGoldenReference(t *testing.T) {
	var out bytes.Buffer

	if err := run(nil, goldenTree(t), &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := out.String(); got != goldenReference {
		t.Fatalf("reference mismatch\ngot:\n%s\nwant:\n%s", got, goldenReference)
	}
}

func TestFail_ReportsTheErrorOnStderr(t *testing.T) {
	var stderr bytes.Buffer

	if code := fail(&stderr, errFailingWriter); code != 1 {
		t.Fatalf("fail = %d, want 1", code)
	}
	if got, want := stderr.String(), "skillgen: write failed\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestFail_ExitsTwoWhenStderrFails(t *testing.T) {
	if code := fail(&failingWriter{}, errFailingWriter); code != 2 {
		t.Fatalf("fail = %d with an unwritable stderr, want 2", code)
	}
}
