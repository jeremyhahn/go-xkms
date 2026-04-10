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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
)

// Extension command errors.
var (
	ErrExtensionInstallFailed   = errors.New("extension: install failed")
	ErrExtensionUninstallFailed = errors.New("extension: uninstall failed")
	ErrExtensionInvalidBrowser  = errors.New("extension: invalid browser (use chrome, firefox, or all)")
	ErrExtensionHostFailed      = errors.New("extension: host failed")
	ErrExtensionUnpairFailed    = errors.New("extension: unpair failed")
)

// allBrowsers is the ordered list of browser families supported for manifest operations.
var allBrowsers = []nativemsg.Browser{
	nativemsg.BrowserChrome,
	nativemsg.BrowserFirefox,
}

// extensionCmd is the parent command for browser extension management.
var extensionCmd = &cobra.Command{
	Use:   "extension",
	Short: "Browser extension management",
	Long:  "Manage browser extension native messaging host manifests for Chrome (and all Chromium-based browsers) and Firefox.",
}

// extensionInstallCmd installs native messaging manifests for the specified browser(s).
var extensionInstallCmd = &cobra.Command{
	Use:   "install [chrome|firefox|all]",
	Short: "Install native messaging manifest",
	Long: `Install the native messaging host manifest for browser extension integration.

The manifest tells the browser how to launch the xkey native messaging host
process. Without a manifest, the browser extension cannot communicate with xkey.

For Chrome, manifests are auto-installed for all detected Chromium-based
browsers (Chrome, Brave, Chromium, Edge). If no Chromium browser is detected,
the manifest is installed to Chrome's default directory.

Use --allowed-origin to override the default Chrome extension origin. This is
useful when loading an unpacked extension with a different extension ID.

Arguments:
  chrome    Install manifest for all Chromium-based browsers (Chrome, Brave, Chromium, Edge)
  firefox   Install manifest for Mozilla Firefox only
  all       Install manifests for all supported browsers (default)

Examples:
  # Install for all browsers
  xkey extension install

  # Install for all Chromium-based browsers
  xkey extension install chrome

  # Install for Firefox only
  xkey extension install firefox

  # Install with a custom Chrome extension origin
  xkey extension install chrome --allowed-origin "chrome-extension://your_extension_id/"`,
	RunE: runExtensionInstall,
}

// extensionUninstallCmd removes native messaging manifests for the specified browser(s).
var extensionUninstallCmd = &cobra.Command{
	Use:   "uninstall [chrome|firefox|all]",
	Short: "Uninstall native messaging manifest",
	Long: `Remove the native messaging host manifest for the specified browser(s).

This prevents the browser extension from launching the xkey native messaging
host process. The xkey binary and configuration are not affected.

For Chrome, manifests are removed from all Chromium-based browser directories
(Chrome, Brave, Chromium, Edge).

Arguments:
  chrome    Uninstall manifests for all Chromium-based browsers
  firefox   Uninstall manifest for Mozilla Firefox only
  all       Uninstall manifests for all supported browsers (default)

Examples:
  # Uninstall for all browsers
  xkey extension uninstall

  # Uninstall for all Chromium-based browsers
  xkey extension uninstall chrome`,
	RunE: runExtensionUninstall,
}

// extensionStatusCmd displays the installation status of native messaging manifests.
var extensionStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show native messaging manifest status",
	Long: `Display the installation status of native messaging host manifests
for all supported browsers.

Shows a table with browser name, installed status, and manifest file path.
For Chromium-based browsers, each derivative (Chrome, Brave, Chromium, Edge)
is shown separately.

Examples:
  xkey extension status`,
	RunE: runExtensionStatus,
}

// extensionHostCmd runs the native messaging host. This command is invoked by
// the browser, not by the user directly.
var extensionHostCmd = &cobra.Command{
	Use:    "host",
	Short:  "Run native messaging host (invoked by browser)",
	Long:   "Run the native messaging host process. This is called by the browser when the extension connects and should not be run manually.",
	Hidden: true,
	RunE:   runExtensionHost,
}

// extensionUnpairCmd removes the paired browser extension identity.
var extensionUnpairCmd = &cobra.Command{
	Use:   "unpair",
	Short: "Remove paired browser extension identity",
	Long: `Remove the paired browser extension Ed25519 identity key.

This deletes the stored pairing state, requiring the extension to complete
a new pairing ceremony before it can communicate with the native messaging host.

Examples:
  xkey extension unpair`,
	RunE: runExtensionUnpair,
}

// extensionPairStatusCmd displays the current extension pairing status.
var extensionPairStatusCmd = &cobra.Command{
	Use:   "pair-status",
	Short: "Show extension pairing status",
	Long: `Display the current browser extension pairing status.

Shows whether an extension is paired, and if so, the origin and pairing timestamp.

Examples:
  xkey extension pair-status`,
	RunE: runExtensionPairStatus,
}

func init() {
	RootCmd.AddCommand(extensionCmd)
	extensionCmd.AddCommand(extensionInstallCmd)
	extensionCmd.AddCommand(extensionUninstallCmd)
	extensionCmd.AddCommand(extensionStatusCmd)
	extensionCmd.AddCommand(extensionHostCmd)
	extensionCmd.AddCommand(extensionUnpairCmd)
	extensionCmd.AddCommand(extensionPairStatusCmd)
	extensionHostCmd.Flags().String("socket", "", "IPC socket path (default: auto-detect)")
	extensionHostCmd.Flags().Bool("no-pairing", false, "Disable extension pairing verification (development only)")
	extensionInstallCmd.Flags().String("allowed-origin", "", "Override Chrome extension allowed origin (e.g., chrome-extension://your_id/)")
}

// parseBrowser resolves a browser argument string into one or more Browser
// values. An empty string or "all" returns all supported browsers.
func parseBrowser(arg string) ([]nativemsg.Browser, error) {
	switch arg {
	case "", "all":
		return allBrowsers, nil
	case "chrome":
		return []nativemsg.Browser{nativemsg.BrowserChrome}, nil
	case "firefox":
		return []nativemsg.Browser{nativemsg.BrowserFirefox}, nil
	default:
		return nil, ErrExtensionInvalidBrowser
	}
}

// browserArg extracts the optional browser argument from the command args,
// defaulting to "all" when no argument is provided.
func browserArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return "all"
}

// runExtensionInstall resolves the xkey binary path and installs native
// messaging manifests for the requested browser(s).
func runExtensionInstall(cmd *cobra.Command, args []string) error {
	browsers, err := parseBrowser(browserArg(args))
	if err != nil {
		return err
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExtensionInstallFailed, err)
	}

	// Apply the allowed-origin override if provided. This sets the
	// package-level variable that GenerateManifest reads for Chrome.
	if origin, _ := cmd.Flags().GetString("allowed-origin"); origin != "" {
		nativemsg.ChromeAllowedOriginOverride = origin
	}

	for _, browser := range browsers {
		if installErr := nativemsg.InstallManifest(browser, binaryPath); installErr != nil {
			return fmt.Errorf("%w: %s: %v", ErrExtensionInstallFailed, browser, installErr)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Installed native messaging manifest for %s\n", browser)
	}

	return nil
}

// runExtensionUninstall removes native messaging manifests for the requested
// browser(s). Missing manifests are reported but do not cause a failure.
func runExtensionUninstall(cmd *cobra.Command, args []string) error {
	browsers, err := parseBrowser(browserArg(args))
	if err != nil {
		return err
	}

	for _, browser := range browsers {
		if uninstallErr := nativemsg.UninstallManifest(browser); uninstallErr != nil {
			if errors.Is(uninstallErr, nativemsg.ErrManifestNotFound) {
				fmt.Fprintf(cmd.OutOrStdout(), "No manifest found for %s (already removed)\n", browser)
				continue
			}
			return fmt.Errorf("%w: %s: %v", ErrExtensionUninstallFailed, browser, uninstallErr)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Uninstalled native messaging manifest for %s\n", browser)
	}

	return nil
}

// runExtensionStatus prints a table showing the manifest installation status
// for each supported browser. Chromium-based browsers are listed individually
// (Chrome, Brave, Chromium, Edge).
func runExtensionStatus(cmd *cobra.Command, args []string) error {
	statuses := nativemsg.GetManifestStatus()

	fmt.Fprintf(cmd.OutOrStdout(), "%-10s %-10s %s\n", "BROWSER", "INSTALLED", "PATH")
	for _, s := range statuses {
		installed := "no"
		if s.Installed {
			installed = "yes"
		}
		path := s.Path
		if path == "" {
			path = "(unavailable)"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-10s %-10s %s\n", s.Name, installed, path)
	}

	return nil
}

// runExtensionHost starts the native messaging host. The browser invokes this
// command via the manifest. Stdout is the native messaging pipe, so all
// logging is directed to stderr AND a log file for diagnostic visibility.
func runExtensionHost(cmd *cobra.Command, args []string) error {
	socketPath, _ := cmd.Flags().GetString("socket")
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	noPairing, _ := cmd.Flags().GetBool("no-pairing")

	// Build a multi-writer: stderr (Chrome captures) + log file (user-visible).
	// The log file allows diagnosing pairing failures since Chrome hides stderr.
	writers := []io.Writer{os.Stderr}
	homeDir, homeErr := os.UserHomeDir()
	if homeErr == nil {
		logDir := filepath.Join(homeDir, ".xkey", "logs")
		if mkErr := os.MkdirAll(logDir, 0700); mkErr == nil {
			logPath := filepath.Join(logDir, "native-host.log")
			f, fErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if fErr == nil {
				defer f.Close()
				writers = append(writers, f)
			}
		}
	}
	logWriter := io.MultiWriter(writers...)

	logger := slog.New(slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	logger.Info("native messaging host starting",
		"socket_path", socketPath,
		"no_pairing", noPairing,
		"pid", os.Getpid(),
		"args", os.Args,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var pairing *nativemsg.PairingVerifier
	if !noPairing {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("%w: cannot determine home directory: %v", ErrExtensionHostFailed, err)
		}
		// Use the same path as the GUI: ~/.xkey/data/extension/pairing.json.
		// The GUI creates this directory in initializeDataDir().
		pairingDir := filepath.Join(homeDir, ".xkey", "data", "extension")
		if mkErr := os.MkdirAll(pairingDir, 0700); mkErr != nil {
			return fmt.Errorf("%w: cannot create pairing directory: %v", ErrExtensionHostFailed, mkErr)
		}
		statePath := filepath.Join(pairingDir, "pairing.json")
		var pairingErr error
		pairing, pairingErr = nativemsg.NewPairingVerifier(statePath)
		if pairingErr != nil {
			return fmt.Errorf("%w: %v", ErrExtensionHostFailed, pairingErr)
		}
	}

	host := nativemsg.NewHost(socketPath, logger, pairing)
	if err := host.Run(ctx); err != nil {
		logger.Error("native messaging host exited with error", "error", err)
		return fmt.Errorf("%w: %v", ErrExtensionHostFailed, err)
	}

	return nil
}

// runExtensionUnpair removes the paired browser extension identity, requiring
// a new pairing ceremony before the extension can reconnect.
func runExtensionUnpair(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("%w: cannot determine home directory: %v", ErrExtensionUnpairFailed, err)
	}

	statePath := filepath.Join(homeDir, ".xkey", "data", "extension", "pairing.json")
	pairing, err := nativemsg.NewPairingVerifier(statePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExtensionUnpairFailed, err)
	}

	if !pairing.IsPaired() {
		fmt.Fprintln(cmd.OutOrStdout(), "No extension is currently paired")
		return nil
	}

	if err := pairing.Unpair(); err != nil {
		return fmt.Errorf("%w: %v", ErrExtensionUnpairFailed, err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Extension unpaired successfully")
	return nil
}

// runExtensionPairStatus displays the current extension pairing status,
// including the paired origin and timestamp when an extension is paired.
func runExtensionPairStatus(cmd *cobra.Command, args []string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("%w: cannot determine home directory: %v", ErrExtensionUnpairFailed, err)
	}

	statePath := filepath.Join(homeDir, ".xkey", "data", "extension", "pairing.json")
	pairing, err := nativemsg.NewPairingVerifier(statePath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrExtensionUnpairFailed, err)
	}

	states := pairing.GetStates()
	if len(states) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Status: Not paired")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-10s %s (%d extension(s))\n", "Status:", "Paired", len(states))
	for origin, state := range states {
		fmt.Fprintf(cmd.OutOrStdout(), "  %-10s %s\n", "Origin:", origin)
		fmt.Fprintf(cmd.OutOrStdout(), "  %-10s %s\n", "Paired at:", state.PairedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}
