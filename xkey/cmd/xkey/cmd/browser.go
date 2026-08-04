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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/truststore"
)

// Browser command errors.
var (
	ErrBrowserLaunchFailed = errors.New("browser: launch failed")
	ErrBrowserNoBrowsers   = errors.New("browser: no Chrome or Firefox browsers detected")
)

// browserCmd is the parent command for secure browser management.
var browserCmd = &cobra.Command{
	Use:   "browser",
	Short: "Secure browser management",
	Long:  "Launch browsers preconfigured with CA certificates from the xkey trust store.",
}

// browserLaunchCmd launches a browser with trust store certificates injected.
var browserLaunchCmd = &cobra.Command{
	Use:   "launch [url]",
	Short: "Launch a browser with trusted CA certificates",
	Long: `Launch a browser preconfigured with all CA certificates from the
xkey trust store. Chrome-family browsers get an NSS cert9.db with the
certificates. Firefox-family browsers get a policies.json overlay.

By default, the first detected Chrome or Firefox browser is used.
Use --browser to specify a particular browser binary.

Extension import (Chrome, isolated mode only):
  --include-extensions imports the user-installed extensions from the
  system default Chrome profile into the isolated profile so browser-
  automation extensions (e.g. Claude in Chrome) are available. Use
  --extension <id> (repeatable) to import only specific extension IDs;
  by default all user-installed extensions are imported. --source-profile
  overrides the source profile (default ~/.config/google-chrome/Default).

Examples:
  xkey browser launch https://example.com
  xkey browser launch --browser /usr/bin/firefox https://internal.corp.local
  xkey browser launch --browser /usr/bin/brave-browser https://myapp.local
  xkey browser launch --include-extensions https://app.local
  xkey browser launch --include-extensions --extension <id> https://app.local`,
	Args: cobra.MaximumNArgs(1),
	RunE: runBrowserLaunch,
}

var (
	browserBinary     string
	browserInclExts   bool
	browserExtIDs     []string
	browserSrcProfile string
)

func init() {
	browserLaunchCmd.Flags().StringVar(&browserBinary, "browser", "",
		"absolute path to browser binary (default: auto-detect first available)")
	browserLaunchCmd.Flags().BoolVar(&browserInclExts, "include-extensions", false,
		"import user-installed extensions from the system default Chrome profile (Chrome isolated mode only)")
	browserLaunchCmd.Flags().StringArrayVar(&browserExtIDs, "extension", nil,
		"restrict --include-extensions to the given extension ID (repeatable; default: all)")
	browserLaunchCmd.Flags().StringVar(&browserSrcProfile, "source-profile", "",
		"source Chrome profile dir to import extensions from (default: ~/.config/google-chrome/Default)")
	browserCmd.AddCommand(browserLaunchCmd)
	RootCmd.AddCommand(browserCmd)
}

// runBrowserLaunch opens the trust store, detects or resolves the target
// browser, injects CA certificates, and launches the browser process.
func runBrowserLaunch(cmd *cobra.Command, args []string) error {
	url := "about:blank"
	if len(args) > 0 {
		url = args[0]
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed, Cause: err}
	}

	xkeyDir := filepath.Join(home, ".xkey")
	logger := slog.Default()

	// Open the trust store from the standard data directory.
	trustStorePath := filepath.Join(xkeyDir, "data", "trust")
	store, err := truststore.NewFileStore(&truststore.FileStoreConfig{
		BaseDir: trustStorePath,
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed,
			Cause: &WrappedError{Msg: fmt.Sprintf("failed to open trust store at %s", trustStorePath), Err: err}}
	}
	defer func() { _ = store.Close() }()

	// Create services.
	trustSvc := services.NewTrustService(store)

	configPath := filepath.Join(xkeyDir, "config", "browser.json")
	browserSvc, err := services.NewBrowserService(configPath, logger)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed,
			Cause: &WrappedError{Msg: "failed to create browser service", Err: err}}
	}

	browsersDir := filepath.Join(xkeyDir, "browsers")
	secureSvc := services.NewSecureBrowserService(browsersDir, browserSvc, trustSvc, logger)

	// Determine browser path: explicit flag or auto-detect.
	browserPath := browserBinary
	if browserPath == "" {
		browsers := secureSvc.DetectBrowsers()
		if len(browsers) == 0 {
			return ErrBrowserNoBrowsers
		}
		browserPath = browsers[0].Path
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Auto-detected: %s (%s)\n",
			browsers[0].Name, browserPath)
	}

	// Launch the browser with trust store certificates injected. The
	// extension-import flags only take effect for Chrome in isolated mode;
	// the service returns a sentinel error for any other combination.
	result, err := secureSvc.LaunchBrowserWithOptions(browserPath, url, services.LaunchOptions{
		IncludeExtensions: browserInclExts,
		ExtensionIDs:      browserExtIDs,
		SourceProfile:     browserSrcProfile,
	})
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrBrowserLaunchFailed, Cause: err}
	}

	if result.ExtensionsImported > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"Launched %s (%s mode, %d certificates, %d extensions)\n",
			result.Family, result.Mode, result.CertCount, result.ExtensionsImported)
		return nil
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Launched %s (%s mode, %d certificates)\n",
		result.Family, result.Mode, result.CertCount)
	return nil
}
