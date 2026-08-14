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
	"io"
	"io/fs"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd"
	"github.com/jeremyhahn/go-xkms/xkey/frontend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui"
)

// guiRun starts the Wails GUI. It is a variable so tests can exercise the
// GUI dispatch branch of run() without opening a window.
var guiRun = gui.Run

// cliExecute runs the cobra command tree. It is a variable for the same
// reason as guiRun.
var cliExecute = cmd.Execute

func main() {
	os.Exit(run(os.Args, os.Stderr))
}

// run is the testable body of main. It returns the process exit code
// instead of calling os.Exit so the dispatch logic (GUI vs CLI, native
// messaging rewrite, error reporting) can be exercised directly.
func run(argv []string, stderr io.Writer) int {
	os.Args = argv

	// Chrome launches native messaging hosts as:
	//   /path/to/xkey chrome-extension://EXTENSION_ID/
	// Detect this and rewrite args so cobra routes to "extension host".
	if isNativeMessagingInvocation(os.Args) {
		os.Args = []string{os.Args[0], "extension", "host"}
	}

	args := os.Args[1:]
	forceGUI := hasFlag(args, "--gui")
	forceCLI := hasFlag(args, "--no-gui") || hasFlag(args, "--help") || hasFlag(args, "-h")

	// If the user provided subcommand arguments (e.g., "phone pair"),
	// treat it as CLI intent unless --gui was explicitly passed.
	if !forceGUI && hasSubcommand(args) {
		forceCLI = true
	}

	if !forceCLI && (forceGUI || hasGUIEnvironment()) {
		if !guiBuildTagPresent {
			printGUIBuildHelp(stderr)
			return 2
		}
		// Initialize logging from CLI flags before starting the GUI so
		// that --log-level and --log-file take effect for all slog output.
		if err := initGUILogging(args); err != nil {
			fmt.Fprintf(stderr, "logging setup error: %v\n", err)
			return 1
		}

		subFS, err := fs.Sub(frontend.Assets, "dist")
		if err != nil {
			fmt.Fprintf(stderr, "failed to load frontend assets: %v\n", err)
			return 1
		}
		gui.Assets = subFS
		gui.FirmwareVersion = gui.ParseFirmwareVersion(cmd.Version)

		if err := guiRun(); err != nil {
			fmt.Fprintf(stderr, "GUI error: %v\n", err)
			return 1
		}
		return 0
	}

	// Strip --no-gui and --gui flags before cobra processes args.
	os.Args = stripFlags(os.Args, "--no-gui", "--gui")
	if err := cliExecute(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

// printGUIBuildHelp explains that the binary lacks Wails GUI support and how
// to rebuild it. Wails' own stub error ("Wails applications will not build
// without the correct build tags.") is opaque, so this replaces it with
// actionable guidance.
func printGUIBuildHelp(w io.Writer) {
	fmt.Fprintln(w, "xkey: this binary was built without GUI support.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "The Wails GUI requires one of the build tags 'production', 'dev', or 'bindings'.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Rebuild with:")
	fmt.Fprintln(w, "  make -C xkey build-local           # recommended; installs frontend + GUI")
	fmt.Fprintln(w, "  make -C xkey build                 # builds inside the Docker builder image")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Or pass tags directly:")
	fmt.Fprintln(w, "  cd xkey && go build -tags 'ble production codec_json' -o xkey ./cmd/xkey")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Or run the CLI explicitly with --no-gui.")
}

// initGUILogging configures the global slog logger for GUI mode by parsing
// --log-level and --log-file directly from the argument list. This mirrors
// the JSON handler configuration used by the CLI's initLogging in root.go.
// When no flags are provided, it defaults to info level on stderr.
func initGUILogging(args []string) error {
	levelStr := extractFlagValue(args, "--log-level")
	filePath := extractFlagValue(args, "--log-file")

	level := parseLogLevel(levelStr)

	var output io.Writer = os.Stderr
	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return &WrappedError{Msg: fmt.Sprintf("open log file %s", filePath), Err: err}
		}
		output = file
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}
	handler := slog.NewJSONHandler(output, opts)
	slog.SetDefault(slog.New(handler))

	return nil
}

// extractFlagValue returns the value for a --flag <value> or --flag=value
// style argument. It returns an empty string when the flag is not present.
func extractFlagValue(args []string, flag string) string {
	eqPrefix := flag + "="
	for i, a := range args {
		if strings.HasPrefix(a, eqPrefix) {
			return a[len(eqPrefix):]
		}
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// parseLogLevel converts a string log level to slog.Level. It matches the
// same mapping used by the CLI in root.go to keep behavior consistent.
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// stripFlags removes the specified flags from the argument list so cobra
// does not see them.
func stripFlags(args []string, flags ...string) []string {
	remove := make(map[string]struct{}, len(flags))
	for _, f := range flags {
		remove[f] = struct{}{}
	}
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if _, ok := remove[a]; !ok {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// hasFlag returns true if the given flag appears anywhere in the argument list.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// hasSubcommand returns true if the argument list contains a CLI subcommand
// (e.g., "phone", "oath", "version"). It skips known meta-flags and global
// flags that accept values so their arguments aren't mistaken for subcommands.
func hasSubcommand(args []string) bool {
	// Meta-flags handled separately by main() - skip them.
	metaFlags := map[string]struct{}{
		"--gui":    {},
		"--no-gui": {},
		"--help":   {},
		"-h":       {},
	}

	// Global flags that consume the next argument as a value.
	// These must be skipped so their values (e.g., "debug" in
	// "--log-level debug") aren't mistaken for subcommands.
	valueTakingFlags := map[string]struct{}{
		"--config":    {},
		"--log-level": {},
		"--log-file":  {},
		"--xkmsd-url": {},
		"--backend":   {},
	}

	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if _, ok := metaFlags[a]; ok {
			continue
		}
		if _, ok := valueTakingFlags[a]; ok {
			skipNext = true
			continue
		}
		// Skip any flag (--foo or -f) or --flag=value forms
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		// Found a positional argument - this is a subcommand
		return true
	}
	return false
}

// nativeHostName is the native messaging host identifier registered with
// browsers. It mirrors nativemsg.NativeHostName without importing the package.
const nativeHostName = "com.automatethethings.xkey"

// isNativeMessagingInvocation returns true when the binary was launched by a
// browser as a native messaging host. Browsers pass different arguments:
//
//   - Chrome: "chrome-extension://EXTENSION_ID/" as a positional argument.
//   - Firefox: the manifest JSON path, e.g.
//     "~/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json"
//
// Since the binary is a cobra CLI app expecting "extension host" as the
// subcommand, this detection allows main() to rewrite os.Args before cobra
// dispatch.
func isNativeMessagingInvocation(args []string) bool {
	if len(args) < 2 {
		return false
	}
	for _, a := range args[1:] {
		// Chrome passes "chrome-extension://ID/" as the sole argument.
		if strings.HasPrefix(a, "chrome-extension://") {
			return true
		}
		// Firefox passes the manifest file path, e.g.:
		//   ~/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json
		if strings.Contains(a, nativeHostName) {
			return true
		}
	}
	return false
}

// hasGUIEnvironment returns true if the current environment appears to
// have a graphical display available. On Linux this checks for X11 or
// Wayland session variables. On macOS and Windows a GUI is assumed.
func hasGUIEnvironment() bool {
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	case "linux":
		if os.Getenv("DISPLAY") != "" {
			return true
		}
		if os.Getenv("WAYLAND_DISPLAY") != "" {
			return true
		}
		return false
	default:
		return false
	}
}
