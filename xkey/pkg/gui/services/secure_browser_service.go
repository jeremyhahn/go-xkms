// Copyright (c) 2025-2026 Jeremy Hahn
// Copyright (c) 2025-2026 Automate The Things, LLC
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

package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nssdb"
)

// trustHashFilePrefix is the file-name prefix used to persist the trust
// store hash for change detection. The full file name is suffixed with
// the resolved target-store key (family + profile mode) so that each
// distinct target NSS database tracks its own last-synced hash. See
// trustHashPath.
//
// Change detection MUST be per-resolved-target-store, not global: the
// store a sync writes to depends on both the browser family and the
// configured profile mode (isolated -> a managed in-profile NSS DB;
// shared chrome -> the user's ~/.pki/nssdb). A single global hash caused
// a launch in one mode to mark a *different* mode's store as up to date,
// so flipping the mode skipped the sync and left that store with stale
// CAs (TLS interstitial in a "trusted" browser).
const trustHashFilePrefix = "trust_hash"

// nssdbCertLabelPrefix is the prefix applied to all certificate labels
// written to NSS databases, enabling bulk removal by prefix.
const nssdbCertLabelPrefix = "xkey-"

// firefoxPoliciesFile is the standard Firefox enterprise policies filename.
const firefoxPoliciesFile = "policies.json"

// LaunchResult describes the outcome of a successful browser launch.
type LaunchResult struct {
	Browser   string `json:"browser"`
	Family    string `json:"family"`
	Mode      string `json:"mode"`
	CertCount int    `json:"cert_count"`
	PID       int    `json:"pid"`

	// ExtensionsImported is the number of extensions copied from the
	// source profile into the isolated profile for this launch. Zero when
	// extension import was not requested.
	ExtensionsImported int `json:"extensions_imported"`
}

// LaunchOptions controls optional behavior of a secure browser launch.
// The zero value preserves the original launch behavior (no extension
// import), so callers that do not need extensions can pass LaunchOptions{}.
type LaunchOptions struct {
	// IncludeExtensions, when true, imports user-installed extensions from
	// the source Chrome profile into the isolated profile. Only valid for
	// Chrome-family browsers in isolated mode. When this field is left
	// false the persisted BrowserConfig.IncludeExtensions value is used
	// instead; a true value here always forces import on (CLI override).
	IncludeExtensions bool

	// ExtensionIDs optionally restricts the import to the listed extension
	// IDs. When empty, all user-installed extensions in the source profile
	// are imported. Ignored unless extension import is active.
	ExtensionIDs []string

	// SourceProfile overrides the source Chrome profile directory to import
	// extensions from. When empty, the platform default
	// (~/.config/google-chrome/Default) is used. Ignored unless extension
	// import is active.
	SourceProfile string
}

// firefoxPolicies represents the Firefox enterprise policies JSON structure.
type firefoxPolicies struct {
	Policies firefoxPolicyCerts `json:"policies"`
}

// firefoxPolicyCerts holds the Certificates policy block.
type firefoxPolicyCerts struct {
	Certificates firefoxCertConfig `json:"Certificates"`
}

// firefoxCertConfig configures certificate import in Firefox policies.
type firefoxCertConfig struct {
	ImportEnterpriseRoots bool     `json:"ImportEnterpriseRoots"`
	Install               []string `json:"Install"`
}

// SecureBrowserService manages browser certificate injection and launch.
// It synchronizes CA certificates from the xkey trust store into
// browser-specific certificate stores (NSS DB for Chrome, enterprise
// policies for Firefox) and launches browsers with the appropriate
// profile configuration.
type SecureBrowserService struct {
	ctx            context.Context
	log            *slog.Logger
	trustService   *TrustService
	browserService *BrowserService
	baseDir        string

	// execCommand creates exec.Cmd instances. Defaults to exec.CommandContext
	// and can be overridden in tests.
	execCommand func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

// NewSecureBrowserService creates a new SecureBrowserService. The baseDir
// is the root directory for browser profile data (e.g., ~/.xkey/browsers/).
func NewSecureBrowserService(
	baseDir string,
	browserSvc *BrowserService,
	trustSvc *TrustService,
	logger *slog.Logger,
) *SecureBrowserService {
	if logger == nil {
		logger = slog.Default()
	}
	return &SecureBrowserService{
		log:            logger.With("service", "secure_browser"),
		trustService:   trustSvc,
		browserService: browserSvc,
		baseDir:        baseDir,
		execCommand:    exec.CommandContext,
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *SecureBrowserService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// LaunchBrowser detects the browser family from the binary path, ensures
// certificates are synchronized, and launches the browser with the
// appropriate profile configuration. The browserPath must be an absolute
// path to a browser binary. The url is the initial page to open.
//
// This preserves the original behavior (no extension import). Callers that
// need extension import use LaunchBrowserWithOptions.
func (s *SecureBrowserService) LaunchBrowser(browserPath, url string) (*LaunchResult, error) {
	return s.LaunchBrowserWithOptions(browserPath, url, LaunchOptions{})
}

// LaunchBrowserWithOptions is the full-featured launch entry point. In
// addition to the base behavior of LaunchBrowser it can import the
// user-installed extensions from the system default Chrome profile into the
// isolated profile (see LaunchOptions). Extension import is only valid for
// Chrome-family browsers in isolated mode; any other combination returns
// ErrSecureBrowserExtImportUnsupported.
func (s *SecureBrowserService) LaunchBrowserWithOptions(
	browserPath, url string,
	opts LaunchOptions,
) (*LaunchResult, error) {
	if browserPath == "" {
		return nil, ErrSecureBrowserEmptyPath
	}
	if url == "" {
		return nil, ErrSecureBrowserEmptyURL
	}

	family := classifyBrowser(browserPath)
	if family == "" {
		return nil, ErrSecureBrowserUnknownFamily
	}

	certs, err := s.trustService.AllCertificates()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrSecureBrowserCertSync, Cause: err}
	}
	if len(certs) == 0 {
		return nil, ErrSecureBrowserNoCerts
	}

	// Synchronize certs if the trust store has changed.
	if err := s.syncIfChanged(family, certs); err != nil {
		return nil, err
	}

	// Determine profile mode.
	mode := s.profileMode(family)

	// Resolve whether extensions should be imported: an explicit CLI
	// override (opts.IncludeExtensions) wins, otherwise fall back to the
	// persisted config value.
	includeExtensions := opts.IncludeExtensions || s.browserService.GetConfig().IncludeExtensions

	// Build command arguments and environment.
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	args, env, err := s.buildLaunchArgs(family, mode, browserPath, url)
	if err != nil {
		return nil, err
	}

	// Import extensions before launch so the seeded profile is on disk
	// when Chrome reads it. Import is gated to Chrome + isolated mode.
	extImported := 0
	if includeExtensions {
		if family != nativemsg.BrowserChrome || mode != ProfileModeIsolated {
			return nil, ErrSecureBrowserExtImportUnsupported
		}
		profileDir := filepath.Join(s.baseDir, "chrome", "profile")
		n, importErr := s.importChromeExtensions(profileDir, opts.SourceProfile, opts.ExtensionIDs)
		if importErr != nil {
			return nil, importErr
		}
		extImported = n
	}

	cmd := s.execCommand(ctx, args[0], args[1:]...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}

	if err := cmd.Start(); err != nil {
		s.log.Error("secure browser launch failed",
			"browser", browserPath,
			"family", string(family),
			"error", err,
		)
		return nil, &SentinelCauseError{Sentinel: ErrSecureBrowserLaunchFailed, Cause: err}
	}

	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}

	s.log.Info("secure browser launched",
		"browser", browserPath,
		"family", string(family),
		"mode", mode,
		"certs", len(certs),
		"extensions", extImported,
		"pid", pid,
	)

	return &LaunchResult{
		Browser:            browserPath,
		Family:             string(family),
		Mode:               mode,
		CertCount:          len(certs),
		PID:                pid,
		ExtensionsImported: extImported,
	}, nil
}

// DetectBrowsers returns browsers detected on the system that belong to
// Chrome or Firefox families. Browsers that cannot be classified (e.g.,
// Safari) are excluded.
func (s *SecureBrowserService) DetectBrowsers() []BrowserInfo {
	all := s.browserService.DetectBrowsers()
	var result []BrowserInfo
	for _, b := range all {
		if b.Path == BrowserSystem {
			continue
		}
		family := classifyBrowser(b.Path)
		if family != "" {
			result = append(result, b)
		}
	}
	return result
}

// Rebuild forces a rebuild of all browser certificate stores regardless
// of the trust hash. This is called by TrustService when certificates
// are mutated.
func (s *SecureBrowserService) Rebuild() error {
	certs, err := s.trustService.AllCertificates()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserCertSync, Cause: err}
	}

	// Rebuild both families. The hash is recorded per resolved target
	// store (family + current mode) only when that family's sync
	// succeeds, so a failed sync does not falsely mark its store as up
	// to date.
	hash := computeTrustHash(certs)

	if syncErr := s.syncChrome(certs); syncErr != nil {
		s.log.Warn("chrome cert sync failed during rebuild", "error", syncErr)
	} else if writeErr := s.writeTrustHash(nativemsg.BrowserChrome, hash); writeErr != nil {
		return writeErr
	}

	if syncErr := s.syncFirefox(certs); syncErr != nil {
		s.log.Warn("firefox cert sync failed during rebuild", "error", syncErr)
	} else if writeErr := s.writeTrustHash(nativemsg.BrowserFirefox, hash); writeErr != nil {
		return writeErr
	}

	return nil
}

// syncIfChanged ensures the resolved target store for the launched
// family is synchronized with the current trust-store contents.
//
// Change detection is per resolved target store, keyed by family and
// the currently configured profile mode (see trustHashPath). The target
// store a sync writes to depends on the mode, so the hash recorded for
// one mode must not suppress a sync after the mode is flipped: doing so
// left the newly selected store (e.g. the isolated NSS DB) holding stale
// CAs from a prior shared-mode launch and produced TLS interstitials in
// a "trusted" browser.
//
// In addition to the hash check we verify that the on-disk artifact for
// the resolved target store (its cert9.db) actually exists. A previous
// session may have populated the store, recorded the hash, then had the
// profile directory wiped externally — without this existence check the
// next launch silently skips the sync and the browser rejects all
// platform certificates as untrusted.
func (s *SecureBrowserService) syncIfChanged(family nativemsg.Browser, certs []*x509.Certificate) error {
	currentHash := computeTrustHash(certs)
	storedHash, hashErr := s.readTrustHash(family)
	if hashErr != nil && !errors.Is(hashErr, fs.ErrNotExist) {
		// A missing hash file (first sync) is expected and already handled
		// below: storedHash stays "" and mismatches currentHash, forcing a
		// sync. Any other read failure (permissions, a corrupted file) is
		// not expected, so it is logged rather than silently treated the
		// same as "never synced" — the effect (force a resync) is
		// identical either way, but only a genuine failure is worth an
		// operator's attention.
		s.log.Warn("failed to read stored trust hash; forcing resync", "family", family, "error", hashErr)
	}

	if currentHash == storedHash && s.browserStorePresent(family) {
		return nil
	}

	var syncErr error
	switch family {
	case nativemsg.BrowserChrome:
		syncErr = s.syncChrome(certs)
	case nativemsg.BrowserFirefox:
		syncErr = s.syncFirefox(certs)
	default:
		return ErrSecureBrowserUnknownFamily
	}
	if syncErr != nil {
		return syncErr
	}

	return s.writeTrustHash(family, currentHash)
}

// syncChrome writes certificates to the NSS database for Chrome.
// For isolated mode, the NSS DB lives inside the managed profile.
// For shared mode, it targets the user's shared ~/.pki/nssdb/.
func (s *SecureBrowserService) syncChrome(certs []*x509.Certificate) error {
	nssdbDir, ok := s.targetNSSDBDir(nativemsg.BrowserChrome)
	if !ok {
		// Resolving the shared ~/.pki/nssdb path failed (no home dir).
		return &SentinelCauseError{Sentinel: ErrSecureBrowserNSSDB, Cause: ErrSecureBrowserHomeDir}
	}
	if err := nssdb.InitDir(nssdbDir); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserNSSDB, Cause: err}
	}

	writer, err := nssdb.NewWriter(nssdbDir)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserNSSDB, Cause: err}
	}
	defer func() { _ = writer.Close() }()

	// Remove all existing xkey-managed certs then re-add.
	if removeErr := writer.RemoveByPrefix(nssdbCertLabelPrefix); removeErr != nil {
		s.log.Warn("failed to remove existing certs from nssdb", "error", removeErr)
	}

	for _, cert := range certs {
		fingerprint := certFingerprint(cert)
		label := nssdbCertLabelPrefix + fingerprint[:16]
		if addErr := writer.AddTrustedCA(cert, label); addErr != nil {
			s.log.Warn("failed to add cert to nssdb",
				"label", label,
				"error", addErr,
			)
		}
	}

	return nil
}

// syncFirefox writes the trust store CA certificates directly into the
// Firefox profile's NSS database (cert9.db).
//
// Firefox enterprise policies (policies.json) are NOT used because Mozilla
// only loads policies.json from system-protected paths
// (/etc/firefox/policies/, <install>/distribution/) — there is no env var
// or per-user override that Firefox honors. NSS DB injection is the only
// mechanism that works reliably for an unprivileged per-profile launcher.
//
// PEM exports + policies.json are still written alongside the NSS DB for
// operator inspection and for shared-profile fallback (where a system
// administrator can copy them into the supported policies path), but the
// NSS DB is the load-bearing artifact.
//
// Each cert is added with the same xkey- label prefix used for Chrome so
// stale entries can be removed cleanly on re-sync.
func (s *SecureBrowserService) syncFirefox(certs []*x509.Certificate) error {
	certsDir := s.firefoxCertsDir()
	if err := os.MkdirAll(certsDir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserCertExport, Cause: err}
	}

	// Remove old PEM files.
	entries, _ := os.ReadDir(certsDir)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pem") {
			_ = os.Remove(filepath.Join(certsDir, entry.Name()))
		}
	}

	// Write each cert as an individual PEM file (operator/audit aid).
	var certPaths []string
	for _, cert := range certs {
		fingerprint := certFingerprint(cert)
		pemPath := filepath.Join(certsDir, fingerprint+".pem")

		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		pemData := pem.EncodeToMemory(block)
		if err := os.WriteFile(pemPath, pemData, 0o600); err != nil {
			return &SentinelCauseError{Sentinel: ErrSecureBrowserCertExport, Cause: err}
		}
		certPaths = append(certPaths, pemPath)
	}

	// Persist policies.json for operators who deploy it system-wide.
	if err := s.writeFirefoxPolicies(certPaths); err != nil {
		return err
	}

	// Inject certs directly into the Firefox profile's NSS DB. This is
	// what Firefox actually reads at startup. For shared profile mode we
	// skip injection (the user's own profile must not be mutated by us).
	if s.profileMode(nativemsg.BrowserFirefox) != ProfileModeIsolated {
		return nil
	}
	return s.injectFirefoxNSSDB(certs)
}

// injectFirefoxNSSDB writes the given CA certificates to the isolated
// Firefox profile's NSS database, replacing any prior xkey-managed
// entries. The profile directory is created if it does not yet exist;
// Firefox accepts a pre-seeded NSS DB and merges its own runtime entries.
func (s *SecureBrowserService) injectFirefoxNSSDB(certs []*x509.Certificate) error {
	nssdbDir := s.firefoxNSSDBDir()
	if err := os.MkdirAll(nssdbDir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserNSSDB, Cause: err}
	}
	if err := nssdb.InitDir(nssdbDir); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserNSSDB, Cause: err}
	}

	writer, err := nssdb.NewWriter(nssdbDir)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserNSSDB, Cause: err}
	}
	defer func() { _ = writer.Close() }()

	if removeErr := writer.RemoveByPrefix(nssdbCertLabelPrefix); removeErr != nil {
		s.log.Warn("failed to remove existing xkey certs from firefox nssdb", "error", removeErr)
	}

	for _, cert := range certs {
		fingerprint := certFingerprint(cert)
		label := nssdbCertLabelPrefix + fingerprint[:16]
		if addErr := writer.AddTrustedCA(cert, label); addErr != nil {
			s.log.Warn("failed to add cert to firefox nssdb",
				"label", label,
				"error", addErr,
			)
		}
	}
	return nil
}

// writeFirefoxPolicies generates and writes the Firefox enterprise policies
// JSON file that instructs Firefox to import the given certificates.
func (s *SecureBrowserService) writeFirefoxPolicies(certPaths []string) error {
	policies := firefoxPolicies{
		Policies: firefoxPolicyCerts{
			Certificates: firefoxCertConfig{
				ImportEnterpriseRoots: true,
				Install:               certPaths,
			},
		},
	}

	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserPolicyWrite, Cause: err}
	}

	policiesPath := s.firefoxPoliciesPath()
	policiesDir := filepath.Dir(policiesPath)
	if err := os.MkdirAll(policiesDir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserPolicyWrite, Cause: err}
	}

	if err := os.WriteFile(policiesPath, data, 0o600); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserPolicyWrite, Cause: err}
	}

	return nil
}

// buildLaunchArgs constructs the command arguments and environment variables
// for launching a browser.
func (s *SecureBrowserService) buildLaunchArgs(
	family nativemsg.Browser,
	mode string,
	browserPath string,
	url string,
) (args []string, env []string, err error) {
	switch family {
	case nativemsg.BrowserChrome:
		args = []string{browserPath}
		if mode == ProfileModeIsolated {
			profileDir := filepath.Join(s.baseDir, "chrome", "profile")
			args = append(args, "--user-data-dir="+profileDir)
			// Chrome on Linux reads its NSS trust database from
			// $HOME/.pki/nssdb regardless of --user-data-dir. Redirect
			// HOME to the isolated profile directory so the in-profile
			// NSS DB at profileDir/.pki/nssdb is what Chrome reads.
			env = []string{"HOME=" + profileDir}

			// Suppress Chrome's first-run experience for the isolated
			// profile. Without this, every launch into a fresh
			// user-data-dir prompts for default browser, metrics
			// opt-in, welcome wizard, search-engine selection, and
			// signin. The combination needed:
			//   1. `--no-first-run` skips the welcome dialog.
			//   2. `--no-default-browser-check` skips the "make
			//      Chrome default" prompt.
			//   3. `--disable-features=...` disables the post-launch
			//      modal dialogs that show on first profile use.
			//   4. A `First Run` sentinel file in the user-data-dir
			//      makes Chrome treat the profile as already-bootstrapped.
			//   5. A `Default/Preferences` file with first-run keys set
			//      to false suppresses opt-in prompts.
			if mkErr := os.MkdirAll(filepath.Join(profileDir, "Default"), 0o700); mkErr != nil {
				err = &SentinelCauseError{Sentinel: ErrSecureBrowserLaunchFailed, Cause: mkErr}
				return
			}
			// Sentinel file — empty, presence is the signal.
			sentinelPath := filepath.Join(profileDir, "First Run")
			if _, statErr := os.Stat(sentinelPath); os.IsNotExist(statErr) {
				if writeErr := os.WriteFile(sentinelPath, []byte{}, 0o600); writeErr != nil {
					err = &SentinelCauseError{Sentinel: ErrSecureBrowserLaunchFailed, Cause: writeErr}
					return
				}
			}
			// Master Preferences (read once on first launch). Sets the
			// keys Chrome checks before showing welcome/metrics/default-
			// browser dialogs. Only written if the file doesn't already
			// exist so existing user preferences aren't clobbered.
			masterPrefsPath := filepath.Join(profileDir, "Default", "Preferences")
			if _, statErr := os.Stat(masterPrefsPath); os.IsNotExist(statErr) {
				masterPrefs := []byte(`{` +
					`"browser":{"has_seen_welcome_page":true,"check_default_browser":false,"show_home_button":false},` +
					`"distribution":{"import_bookmarks":false,"import_history":false,"import_search_engine":false,` +
					`"make_chrome_default":false,"make_chrome_default_for_user":false,"skip_first_run_ui":true,` +
					`"do_not_create_any_shortcuts":true,"do_not_create_desktop_shortcut":true,` +
					`"do_not_create_quick_launch_shortcut":true,"do_not_create_taskbar_shortcut":true,` +
					`"do_not_launch_chrome":false,"do_not_register_for_update_launch":true,` +
					`"suppress_first_run_default_browser_prompt":true,"suppress_first_run_bubble":true,` +
					`"verbose_logging":false,"welcome_page_on_os_upgrade_enabled":false},` +
					`"first_run_tabs":[],` +
					`"profile":{"default_content_setting_values":{"notifications":2}},` +
					`"sync_promo":{"show_on_first_run_allowed":false,"user_skipped":true},` +
					`"signin":{"allowed":false,"allowed_on_next_startup":false},` +
					`"metrics_reporting_enabled":false}`)
				if writeErr := os.WriteFile(masterPrefsPath, masterPrefs, 0o600); writeErr != nil {
					err = &SentinelCauseError{Sentinel: ErrSecureBrowserLaunchFailed, Cause: writeErr}
					return
				}
			}

			args = append(args,
				"--no-first-run",
				"--no-default-browser-check",
				"--disable-features=ChromeWhatsNewUI,PrivacySandboxSettings4,SyncPromoAfterSigninIntercept",
				"--disable-search-engine-choice-screen",
				"--disable-sync",
				"--ash-no-nudges",
				"--no-service-autorun",
				"--password-store=basic",
				"--use-mock-keychain",
				"--disable-background-mode",
			)
			// Hostname resolution belongs on the host's resolver — the
			// operator points systemd-resolved (or local dnsmasq) at the
			// platform CP's DNS service. We don't paper over that here.
		}
		args = append(args, url)

	case nativemsg.BrowserFirefox:
		args = []string{browserPath}
		// Firefox loads its trust roots from the profile's cert9.db.
		// syncFirefox seeds that NSS DB with xkey-managed CAs so no
		// launch-time env var or argument is required.
		if mode == ProfileModeIsolated {
			profileDir := filepath.Join(s.baseDir, "firefox", "profile")
			if mkErr := os.MkdirAll(profileDir, 0o700); mkErr != nil {
				err = &SentinelCauseError{Sentinel: ErrSecureBrowserLaunchFailed, Cause: mkErr}
				return
			}
			args = append(args, "--profile", profileDir)
		}
		args = append(args, url)

	default:
		err = ErrSecureBrowserUnknownFamily
	}

	return
}

// profileMode returns the configured profile mode for the given browser
// family, defaulting to isolated.
func (s *SecureBrowserService) profileMode(family nativemsg.Browser) string {
	config := s.browserService.GetConfig()
	switch family {
	case nativemsg.BrowserChrome:
		if config.ChromeProfileMode == ProfileModeShared {
			return ProfileModeShared
		}
	case nativemsg.BrowserFirefox:
		if config.FirefoxProfileMode == ProfileModeShared {
			return ProfileModeShared
		}
	}
	return ProfileModeIsolated
}

// chromeNSSDBDir returns the NSS database directory for isolated Chrome profiles.
// The path uses the standard NSS dotfile layout (.pki/nssdb) so that when the
// browser is launched with HOME pointed at the profile directory Chrome's
// built-in lookup of $HOME/.pki/nssdb resolves to this database.
func (s *SecureBrowserService) chromeNSSDBDir() string {
	return filepath.Join(s.baseDir, "chrome", "profile", ".pki", "nssdb")
}

// firefoxCertsDir returns the directory for Firefox PEM certificate files.
func (s *SecureBrowserService) firefoxCertsDir() string {
	return filepath.Join(s.baseDir, "firefox", "certs")
}

// firefoxPoliciesPath returns the path to the Firefox policies.json file.
func (s *SecureBrowserService) firefoxPoliciesPath() string {
	return filepath.Join(s.baseDir, "firefox", firefoxPoliciesFile)
}

// firefoxNSSDBDir returns the NSS database directory inside the isolated
// Firefox profile. Firefox reads its trust roots from cert9.db located
// directly in the profile directory (no .pki/nssdb subpath).
func (s *SecureBrowserService) firefoxNSSDBDir() string {
	return filepath.Join(s.baseDir, "firefox", "profile")
}

// browserStorePresent verifies the on-disk NSS database that the
// resolved target store for the given family and its currently
// configured profile mode would write to actually exists. Used as a
// guard so the hash-only short-circuit in syncIfChanged doesn't skip
// work when the target store has been wiped between launches.
//
// The probe targets the load-bearing artifact: cert9.db (the NSS
// database the browser actually reads at startup). It is resolved per
// mode because the target store differs by mode — checking the isolated
// store while running in shared mode (or vice versa) would let the
// short-circuit skip a genuinely stale store.
//
// Shared chrome targets the user's real ~/.pki/nssdb; we only probe it
// for existence and never write xkey bookkeeping there.
func (s *SecureBrowserService) browserStorePresent(family nativemsg.Browser) bool {
	dir, ok := s.targetNSSDBDir(family)
	if !ok {
		// No NSS DB target for this combination (shared firefox writes
		// only PEM/policies, which the wiped-store guard does not track).
		return true
	}
	_, err := os.Stat(filepath.Join(dir, "cert9.db"))
	return err == nil
}

// targetNSSDBDir returns the NSS database directory that a sync for the
// given family writes to under the currently configured profile mode,
// and whether such an NSS DB target exists for that combination.
//
// Combinations:
//   - chrome isolated  -> the managed in-profile NSS DB
//   - chrome shared    -> the user's ~/.pki/nssdb
//   - firefox isolated -> the managed in-profile NSS DB
//   - firefox shared   -> no NSS DB injection (false)
func (s *SecureBrowserService) targetNSSDBDir(family nativemsg.Browser) (string, bool) {
	mode := s.profileMode(family)
	switch family {
	case nativemsg.BrowserChrome:
		if mode == ProfileModeShared {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", false
			}
			return filepath.Join(home, ".pki", "nssdb"), true
		}
		return s.chromeNSSDBDir(), true
	case nativemsg.BrowserFirefox:
		if mode == ProfileModeShared {
			return "", false
		}
		return s.firefoxNSSDBDir(), true
	}
	return "", false
}

// trustHashPath returns the path of the per-resolved-target-store trust
// hash file for the given family under its currently configured profile
// mode. The file is keyed by family + mode so each distinct target NSS
// database tracks its own last-synced hash.
//
// All bookkeeping lives under s.baseDir — never inside the user's real
// ~/.pki/nssdb that shared-mode chrome writes to.
func (s *SecureBrowserService) trustHashPath(family nativemsg.Browser) string {
	mode := s.profileMode(family)
	name := trustHashFilePrefix + "." + string(family) + "." + mode
	return filepath.Join(s.baseDir, name)
}

// readTrustHash reads the stored trust hash for the resolved target
// store of the given family from disk.
func (s *SecureBrowserService) readTrustHash(family nativemsg.Browser) (string, error) {
	data, err := os.ReadFile(s.trustHashPath(family))
	if err != nil {
		return "", &SentinelCauseError{Sentinel: ErrSecureBrowserHashRead, Cause: err}
	}
	return strings.TrimSpace(string(data)), nil
}

// writeTrustHash persists the trust hash for the resolved target store
// of the given family to disk.
func (s *SecureBrowserService) writeTrustHash(family nativemsg.Browser, hash string) error {
	if err := os.MkdirAll(s.baseDir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserHashWrite, Cause: err}
	}
	if err := os.WriteFile(s.trustHashPath(family), []byte(hash), 0o600); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserHashWrite, Cause: err}
	}
	return nil
}

// classifyBrowser determines the browser family from a binary path by
// matching the base name against known browser names.
func classifyBrowser(browserPath string) nativemsg.Browser {
	base := strings.ToLower(filepath.Base(browserPath))

	// Chrome family keywords.
	chromeKeywords := []string{"chrome", "chromium", "brave", "edge", "opera", "vivaldi"}
	for _, kw := range chromeKeywords {
		if strings.Contains(base, kw) {
			return nativemsg.BrowserChrome
		}
	}

	// Firefox family keywords.
	firefoxKeywords := []string{"firefox", "librewolf", "waterfox"}
	for _, kw := range firefoxKeywords {
		if strings.Contains(base, kw) {
			return nativemsg.BrowserFirefox
		}
	}

	return ""
}

// trustHashImplVersion is mixed into computeTrustHash so that on-disk
// hashes from prior xkey versions are invalidated when the sync logic
// itself changes. Bump this whenever the set of files written by
// syncChrome/syncFirefox changes in a way that requires a rebuild for
// previously-synced profiles. v2: Firefox now writes its NSS DB
// directly (the policies.json env-var path was non-functional).
const trustHashImplVersion = "v2"

// computeTrustHash computes a deterministic SHA-256 hash over the
// implementation version and all certificate fingerprints in sorted
// order. This serves as a change detection mechanism.
func computeTrustHash(certs []*x509.Certificate) string {
	fingerprints := make([]string, len(certs))
	for i, cert := range certs {
		fingerprints[i] = certFingerprint(cert)
	}
	sort.Strings(fingerprints)
	h := sha256.Sum256([]byte(trustHashImplVersion + "|" + strings.Join(fingerprints, "")))
	return hex.EncodeToString(h[:])
}

// certFingerprint returns the hex-encoded SHA-256 fingerprint of a certificate.
func certFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}
