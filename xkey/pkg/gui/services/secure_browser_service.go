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
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/nativemsg"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/nssdb"
)

// trustHashFile is the file name used to persist the trust store hash
// for change detection.
const trustHashFile = "trust_hash"

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
func (s *SecureBrowserService) LaunchBrowser(browserPath, url string) (*LaunchResult, error) {
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
		return nil, fmt.Errorf("%w: %w", ErrSecureBrowserCertSync, err)
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

	// Build command arguments and environment.
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	args, env, err := s.buildLaunchArgs(family, mode, browserPath, url)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("%w: %w", ErrSecureBrowserLaunchFailed, err)
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
		"pid", pid,
	)

	return &LaunchResult{
		Browser:   browserPath,
		Family:    string(family),
		Mode:      mode,
		CertCount: len(certs),
		PID:       pid,
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
		return fmt.Errorf("%w: %w", ErrSecureBrowserCertSync, err)
	}

	// Rebuild both families.
	if syncErr := s.syncChrome(certs); syncErr != nil {
		s.log.Warn("chrome cert sync failed during rebuild", "error", syncErr)
	}
	if syncErr := s.syncFirefox(certs); syncErr != nil {
		s.log.Warn("firefox cert sync failed during rebuild", "error", syncErr)
	}

	// Update the trust hash.
	hash := computeTrustHash(certs)
	if writeErr := s.writeTrustHash(hash); writeErr != nil {
		return writeErr
	}

	return nil
}

// syncIfChanged checks the trust hash and rebuilds browser cert stores
// for both families if the trust store contents have changed.
//
// In addition to the hash check we verify that the on-disk artifacts
// (Chrome's NSS DB, Firefox's certs dir) actually exist. A previous
// session may have populated them, recorded the hash, then had the
// profile directory wiped externally — without this existence check
// the next launch silently skips the sync and Chrome rejects all
// platform certificates as untrusted.
func (s *SecureBrowserService) syncIfChanged(family nativemsg.Browser, certs []*x509.Certificate) error {
	currentHash := computeTrustHash(certs)
	storedHash, _ := s.readTrustHash()

	if currentHash == storedHash && s.browserStoresPresent(family) {
		return nil
	}

	// Sync both families since the hash is shared. Log warnings for
	// the non-launched family but return errors only for the target.
	if syncErr := s.syncChrome(certs); syncErr != nil {
		if family == nativemsg.BrowserChrome {
			return syncErr
		}
		s.log.Warn("chrome cert sync failed", "error", syncErr)
	}
	if syncErr := s.syncFirefox(certs); syncErr != nil {
		if family == nativemsg.BrowserFirefox {
			return syncErr
		}
		s.log.Warn("firefox cert sync failed", "error", syncErr)
	}

	return s.writeTrustHash(currentHash)
}

// syncChrome writes certificates to the NSS database for Chrome.
// For isolated mode, the NSS DB lives inside the managed profile.
// For shared mode, it targets the user's shared ~/.pki/nssdb/.
func (s *SecureBrowserService) syncChrome(certs []*x509.Certificate) error {
	nssdbDir := s.chromeNSSDBDir()
	mode := s.profileMode(nativemsg.BrowserChrome)
	if mode == ProfileModeShared {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSecureBrowserNSSDB, err)
		}
		nssdbDir = filepath.Join(home, ".pki", "nssdb")
	}
	if err := nssdb.InitDir(nssdbDir); err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserNSSDB, err)
	}

	writer, err := nssdb.NewWriter(nssdbDir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserNSSDB, err)
	}
	defer writer.Close()

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
		return fmt.Errorf("%w: %w", ErrSecureBrowserCertExport, err)
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
			return fmt.Errorf("%w: %w", ErrSecureBrowserCertExport, err)
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
		return fmt.Errorf("%w: %w", ErrSecureBrowserNSSDB, err)
	}
	if err := nssdb.InitDir(nssdbDir); err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserNSSDB, err)
	}

	writer, err := nssdb.NewWriter(nssdbDir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserNSSDB, err)
	}
	defer writer.Close()

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
		return fmt.Errorf("%w: %w", ErrSecureBrowserPolicyWrite, err)
	}

	policiesPath := s.firefoxPoliciesPath()
	policiesDir := filepath.Dir(policiesPath)
	if err := os.MkdirAll(policiesDir, 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserPolicyWrite, err)
	}

	if err := os.WriteFile(policiesPath, data, 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserPolicyWrite, err)
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
				err = fmt.Errorf("%w: %w", ErrSecureBrowserLaunchFailed, mkErr)
				return
			}
			// Sentinel file — empty, presence is the signal.
			sentinelPath := filepath.Join(profileDir, "First Run")
			if _, statErr := os.Stat(sentinelPath); os.IsNotExist(statErr) {
				if writeErr := os.WriteFile(sentinelPath, []byte{}, 0o600); writeErr != nil {
					err = fmt.Errorf("%w: %w", ErrSecureBrowserLaunchFailed, writeErr)
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
					err = fmt.Errorf("%w: %w", ErrSecureBrowserLaunchFailed, writeErr)
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
				err = fmt.Errorf("%w: %w", ErrSecureBrowserLaunchFailed, mkErr)
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

// browserStoresPresent verifies the on-disk artifacts that syncChrome
// and syncFirefox produce actually exist. Used as a guard so the
// hash-only short-circuit in syncIfChanged doesn't skip work when the
// browser profile or cert directory has been wiped between launches.
//
// The probe targets the load-bearing artifact for each browser:
// cert9.db (the NSS database both Chrome and Firefox actually read at
// startup). Verifying policies.json for Firefox would not catch a wiped
// NSS DB, leaving Firefox launching without any xkey-managed CAs.
func (s *SecureBrowserService) browserStoresPresent(family nativemsg.Browser) bool {
	switch family {
	case nativemsg.BrowserChrome:
		_, err := os.Stat(filepath.Join(s.chromeNSSDBDir(), "cert9.db"))
		return err == nil
	case nativemsg.BrowserFirefox:
		_, err := os.Stat(filepath.Join(s.firefoxNSSDBDir(), "cert9.db"))
		return err == nil
	}
	return false
}

// readTrustHash reads the stored trust hash from disk.
func (s *SecureBrowserService) readTrustHash() (string, error) {
	data, err := os.ReadFile(filepath.Join(s.baseDir, trustHashFile))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSecureBrowserHashRead, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// writeTrustHash persists the trust hash to disk.
func (s *SecureBrowserService) writeTrustHash(hash string) error {
	if err := os.MkdirAll(s.baseDir, 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserHashWrite, err)
	}
	if err := os.WriteFile(filepath.Join(s.baseDir, trustHashFile), []byte(hash), 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrSecureBrowserHashWrite, err)
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
