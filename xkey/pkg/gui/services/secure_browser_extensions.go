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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Extension import is a Chrome-only, isolated-mode capability that copies
// the user-installed extensions (e.g. "Claude in Chrome") from the system
// default Chrome profile into the xkey-managed isolated profile so the
// browser-automation extension is present in the sandboxed browser.
//
// MECHANISM (Linux, Google-branded Chrome 137+):
//
//   - `--load-extension` is IGNORED by branded Chrome 137+, so it cannot be
//     used. The only reliable approach is to materialize the extension into
//     the profile exactly as Chrome's own installer would: copy the unpacked
//     version directory under Default/Extensions/<id>/<version>/ AND register
//     it in the profile's preferences under extensions.settings.<id>.
//
//   - Chrome stores the extension registration in one of two JSON files in
//     the profile: "Secure Preferences" (MAC-protected; where branded Chrome
//     normally writes extension settings) or "Preferences". We copy the
//     registration entry faithfully from whichever source file holds it into
//     the SAME-named file in the isolated profile. Linux Chrome does not
//     enforce the Secure Preferences super-MAC the way Windows/macOS do, so a
//     faithfully-copied entry is accepted; we do not recompute MACs.
//
//   - Merge semantics: the isolated profile persists across launches and the
//     user may have changed settings there, so we read the existing target
//     JSON, merge only extensions.settings.<id> into it, and write it back.
//     We never clobber unrelated keys.
//
// PRIVACY: only the explicit allowlist below is copied. Cookies, Login Data,
// History, Sessions, Web Data, and every other profile artifact are left in
// the source profile — the sandbox's isolation is the whole point.

// chromeExtensionsSubdir is the per-profile directory that holds unpacked
// extension version directories: <profile>/Default/Extensions/<id>/<ver>/.
const chromeExtensionsSubdir = "Extensions"

// chromeLocalExtSettingsSubdir holds per-extension LevelDB state
// (chrome.storage.local): <profile>/Default/Local Extension Settings/<id>/.
const chromeLocalExtSettingsSubdir = "Local Extension Settings"

// chromeIndexedDBSubdir holds per-origin IndexedDB stores. Extension
// IndexedDB lives at chrome-extension_<id>_0.indexeddb.leveldb inside it.
const chromeIndexedDBSubdir = "IndexedDB"

// chromeSecurePreferences and chromePreferences are the two profile files
// that may contain the extensions.settings registration. Secure Preferences
// is preferred by branded Chrome; Preferences is the fallback.
const (
	chromeSecurePreferences = "Secure Preferences"
	chromePreferences       = "Preferences"
)

// chromeSourceNMHRelDir is the native-messaging-host manifest directory
// relative to the real user HOME, where Chrome's installer writes user-level
// host manifests for default installs.
var chromeSourceNMHRelDir = filepath.Join(".config", "google-chrome", "NativeMessagingHosts")

// chromeProfileNMHSubdir is the native-messaging-host manifest directory that
// isolated Chrome actually reads. With --user-data-dir set, Chrome resolves
// user-level NMH manifests from chrome::DIR_USER_NATIVE_MESSAGING, which is
// <user-data-dir>/NativeMessagingHosts (NOT <HOME>/.config/google-chrome/...).
// For default installs the user-data-dir IS ~/.config/google-chrome, which is
// why a $HOME-relative path coincidentally appeared correct.
const chromeProfileNMHSubdir = "NativeMessagingHosts"

// chromeNMHWrapperSubdir holds generated wrapper scripts that restore the real
// user HOME before exec-ing the original native-messaging host binary. The
// isolated browser launches with HOME redirected to the profile directory (for
// NSS), which Chrome propagates to spawned hosts; hosts that resolve state
// under $HOME (e.g. the Claude host under ~/.claude) would otherwise break.
const chromeNMHWrapperSubdir = "nmh-wrappers"

// importChromeExtensions imports the requested extensions from the source
// Chrome profile into the isolated profile and mirrors the native-messaging
// host manifests so extensions that talk to a local helper (e.g. Claude in
// Chrome) can connect. It returns the number of extensions imported.
//
// profileDir is the isolated --user-data-dir (HOME is redirected here at
// launch). sourceProfile overrides the default source profile when non-empty.
// idFilter, when non-empty, restricts the import to those extension IDs.
func (s *SecureBrowserService) importChromeExtensions(
	profileDir, sourceProfile string,
	idFilter []string,
) (int, error) {
	source, err := s.resolveSourceProfile(sourceProfile)
	if err != nil {
		return 0, err
	}

	srcExtDir := filepath.Join(source, chromeExtensionsSubdir)
	ids, err := s.selectExtensionIDs(srcExtDir, idFilter)
	if err != nil {
		return 0, err
	}

	// Load the source registration map from whichever preferences file
	// holds it, so we can copy each extension's entry into the matching
	// target file faithfully.
	srcSecure := loadExtensionSettings(filepath.Join(source, chromeSecurePreferences))
	srcPlain := loadExtensionSettings(filepath.Join(source, chromePreferences))

	imported := 0
	var secureMerge, plainMerge map[string]json.RawMessage

	for _, id := range ids {
		if entry, ok := srcSecure[id]; ok {
			if secureMerge == nil {
				secureMerge = make(map[string]json.RawMessage)
			}
			secureMerge[id] = entry
		} else if entry, ok := srcPlain[id]; ok {
			if plainMerge == nil {
				plainMerge = make(map[string]json.RawMessage)
			}
			plainMerge[id] = entry
		} else {
			// No registration for this id — copying the version dir alone
			// would not surface the extension, so skip it cleanly.
			s.log.Warn("skipping extension with no registration entry",
				"id", id, "source", source)
			continue
		}

		if err := s.copyExtensionVersionDir(srcExtDir, profileDir, id); err != nil {
			return imported, err
		}
		if err := s.copyExtensionState(source, profileDir, id); err != nil {
			return imported, err
		}
		imported++
	}

	// Merge registrations into the target preferences files (never clobber).
	if len(secureMerge) > 0 {
		target := filepath.Join(profileDir, "Default", chromeSecurePreferences)
		if err := mergeExtensionSettings(target, secureMerge); err != nil {
			return imported, err
		}
	}
	if len(plainMerge) > 0 {
		target := filepath.Join(profileDir, "Default", chromePreferences)
		if err := mergeExtensionSettings(target, plainMerge); err != nil {
			return imported, err
		}
	}

	if err := s.mirrorNativeMessagingHosts(profileDir); err != nil {
		return imported, err
	}

	return imported, nil
}

// resolveSourceProfile resolves and validates the source Chrome profile
// directory, defaulting to ~/.config/google-chrome/Default.
func (s *SecureBrowserService) resolveSourceProfile(override string) (string, error) {
	source := override
	if source == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", &SentinelCauseError{Sentinel: ErrSecureBrowserHomeDir, Cause: err}
		}
		source = filepath.Join(home, ".config", "google-chrome", "Default")
	}
	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return "", &DetailError{Err: ErrSecureBrowserSourceProfile, Detail: fmt.Sprintf(": %s", source)}
	}
	return source, nil
}

// selectExtensionIDs returns the extension IDs to import. When idFilter is
// non-empty only those ids are returned (and only if present on disk);
// otherwise every user-installed extension directory under srcExtDir is
// returned. A missing Extensions directory yields an empty result, not an
// error — a profile may simply have no extensions.
func (s *SecureBrowserService) selectExtensionIDs(srcExtDir string, idFilter []string) ([]string, error) {
	entries, err := os.ReadDir(srcExtDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	present := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			present[e.Name()] = struct{}{}
		}
	}

	if len(idFilter) > 0 {
		var ids []string
		for _, id := range idFilter {
			if _, ok := present[id]; ok {
				ids = append(ids, id)
			} else {
				s.log.Warn("requested extension id not found in source profile",
					"id", id, "source", srcExtDir)
			}
		}
		return ids, nil
	}

	ids := make([]string, 0, len(present))
	for id := range present {
		ids = append(ids, id)
	}
	return ids, nil
}

// copyExtensionVersionDir copies the latest unpacked version directory of an
// extension from the source profile into the isolated profile. Re-import is
// idempotent: if the destination already holds the same version-named
// directory it is refreshed; older versions are left in place (Chrome reads
// the version recorded in the registration entry).
func (s *SecureBrowserService) copyExtensionVersionDir(srcExtDir, profileDir, id string) error {
	srcIDDir := filepath.Join(srcExtDir, id)
	versions, err := os.ReadDir(srcIDDir)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	dstIDDir := filepath.Join(profileDir, "Default", chromeExtensionsSubdir, id)
	for _, v := range versions {
		if !v.IsDir() {
			continue
		}
		src := filepath.Join(srcIDDir, v.Name())
		dst := filepath.Join(dstIDDir, v.Name())
		if err := copyTree(src, dst); err != nil {
			return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
		}
	}
	return nil
}

// copyExtensionState mirrors the per-extension LevelDB state directories
// (chrome.storage.local and IndexedDB) so authentication and runtime state
// carry over. Each is optional: absence is skipped silently.
func (s *SecureBrowserService) copyExtensionState(source, profileDir, id string) error {
	// chrome.storage.local — Default/Local Extension Settings/<id>/
	srcLocal := filepath.Join(source, chromeLocalExtSettingsSubdir, id)
	if dirExists(srcLocal) {
		dstLocal := filepath.Join(profileDir, "Default", chromeLocalExtSettingsSubdir, id)
		if err := copyTree(srcLocal, dstLocal); err != nil {
			return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
		}
	}

	// IndexedDB — Default/IndexedDB/chrome-extension_<id>_0.indexeddb.leveldb
	idbName := "chrome-extension_" + id + "_0.indexeddb.leveldb"
	srcIDB := filepath.Join(source, chromeIndexedDBSubdir, idbName)
	if dirExists(srcIDB) {
		dstIDB := filepath.Join(profileDir, "Default", chromeIndexedDBSubdir, idbName)
		if err := copyTree(srcIDB, dstIDB); err != nil {
			return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
		}
	}
	return nil
}

// mirrorNativeMessagingHosts regenerates the native-messaging-host manifest
// set the isolated browser reads, deriving it from the user's real host
// manifests. For each source manifest it writes two artifacts under the
// profile:
//
//   - <profileDir>/nmh-wrappers/<host-name>.sh — an executable wrapper that
//     restores the REAL user HOME (resolved here, NOT from the redirected
//     launch env) and execs the original host binary. The isolated browser
//     launches with HOME redirected to the profile (for NSS) and Chrome
//     propagates that to spawned hosts, so a host that resolves its state
//     under $HOME (e.g. the Claude host under ~/.claude) breaks without this.
//
//   - <profileDir>/NativeMessagingHosts/<name>.json — the source manifest
//     copied verbatim except its "path" points at the wrapper. This is the
//     directory Chrome's chrome::DIR_USER_NATIVE_MESSAGING resolves to when
//     --user-data-dir is set.
//
// Generation is idempotent: both artifacts are rewritten on every import so a
// changed source manifest (e.g. an upgraded host path) is reflected. If no
// real home or no source manifests exist the step is a clean no-op.
func (s *SecureBrowserService) mirrorNativeMessagingHosts(profileDir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserHomeDir, Cause: err}
	}

	srcDir := filepath.Join(home, chromeSourceNMHRelDir)
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	manifestDir := filepath.Join(profileDir, chromeProfileNMHSubdir)
	wrapperDir := filepath.Join(profileDir, chromeNMHWrapperSubdir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(srcDir, e.Name())
		if err := s.generateNativeMessagingHost(src, e.Name(), home, manifestDir, wrapperDir); err != nil {
			return err
		}
	}
	return nil
}

// generateNativeMessagingHost reads a single source NMH manifest and writes the
// wrapper script and rewritten manifest for it under the profile. realHome is
// the resolved real user home that the wrapper restores. The original manifest
// fields (name, description, type, allowed_origins, ...) are preserved verbatim
// — only "path" is rewritten to point at the generated wrapper.
func (s *SecureBrowserService) generateNativeMessagingHost(
	srcManifest, fileName, realHome, manifestDir, wrapperDir string,
) error {
	data, err := os.ReadFile(srcManifest)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	// Preserve every manifest field; rewrite only "path". An ordered decode is
	// not needed — Chrome reads the manifest as a JSON object.
	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(data, &manifest); err != nil {
		return &DetailError{Err: ErrSecureBrowserExtImport, Detail: fmt.Sprintf(": corrupt native messaging host manifest %s", srcManifest)}
	}

	var hostPath string
	if raw, ok := manifest["path"]; ok {
		if err := json.Unmarshal(raw, &hostPath); err != nil {
			return &DetailError{Err: ErrSecureBrowserExtImport, Detail: fmt.Sprintf(": corrupt path in native messaging host manifest %s", srcManifest)}
		}
	}
	if hostPath == "" {
		// No host binary to wrap — nothing actionable; skip cleanly.
		s.log.Warn("skipping native messaging host manifest with no path",
			"manifest", srcManifest)
		return nil
	}

	// Derive a stable wrapper name from the manifest file name.
	wrapperName := nmhWrapperName(fileName)
	wrapperPath := filepath.Join(wrapperDir, wrapperName)

	if err := os.MkdirAll(wrapperDir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	wrapper := buildNMHWrapperScript(realHome, hostPath)
	if err := os.WriteFile(wrapperPath, []byte(wrapper), 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	// WriteFile honors the mode only when creating; on idempotent re-import the
	// file already exists, so force the executable mode explicitly.
	if err := os.Chmod(wrapperPath, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	rewrittenPath, err := json.Marshal(wrapperPath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	manifest["path"] = rewrittenPath

	out, err := json.Marshal(manifest)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	dstManifest := filepath.Join(manifestDir, fileName)
	if err := os.WriteFile(dstManifest, out, 0o600); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	return nil
}

// nmhWrapperName maps a manifest file name to its wrapper script file name,
// replacing a trailing ".json" with ".sh".
func nmhWrapperName(manifestFile string) string {
	base := strings.TrimSuffix(manifestFile, filepath.Ext(manifestFile))
	return base + ".sh"
}

// buildNMHWrapperScript renders a POSIX shell wrapper that restores the real
// user HOME and execs the original host binary, forwarding all arguments.
func buildNMHWrapperScript(realHome, hostPath string) string {
	return "#!/bin/sh\n" +
		"export HOME=" + shellSingleQuote(realHome) + "\n" +
		"exec " + shellSingleQuote(hostPath) + " \"$@\"\n"
}

// shellSingleQuote returns s wrapped in single quotes, safe for POSIX shells,
// escaping any embedded single quotes.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// loadExtensionSettings reads the extensions.settings.<id> registration map
// from a Chrome preferences file. A missing or unparseable file yields an
// empty map (the caller falls back to the other preferences file).
func loadExtensionSettings(path string) map[string]json.RawMessage {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil {
		return nil
	}
	extRaw, ok := root["extensions"]
	if !ok {
		return nil
	}
	var ext map[string]json.RawMessage
	if json.Unmarshal(extRaw, &ext) != nil {
		return nil
	}
	settingsRaw, ok := ext["settings"]
	if !ok {
		return nil
	}
	var settings map[string]json.RawMessage
	if json.Unmarshal(settingsRaw, &settings) != nil {
		return nil
	}
	return settings
}

// mergeExtensionSettings merges the given extensions.settings entries into
// the target Chrome preferences file, preserving every pre-existing key. If
// the target file does not exist it is created with a minimal structure. The
// merge is performed at the JSON-object level so unrelated top-level keys,
// the rest of the extensions object, and other extensions.settings entries
// all survive.
func mergeExtensionSettings(path string, entries map[string]json.RawMessage) error {
	root := map[string]json.RawMessage{}
	if data, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(data, &root) != nil {
			// Refuse to clobber an unparseable existing profile file.
			return &DetailError{Err: ErrSecureBrowserExtImport, Detail: fmt.Sprintf(": corrupt preferences file %s", path)}
		}
	}

	ext := map[string]json.RawMessage{}
	if raw, ok := root["extensions"]; ok {
		if json.Unmarshal(raw, &ext) != nil {
			return &DetailError{Err: ErrSecureBrowserExtImport, Detail: fmt.Sprintf(": corrupt extensions block in %s", path)}
		}
	}

	settings := map[string]json.RawMessage{}
	if raw, ok := ext["settings"]; ok {
		if json.Unmarshal(raw, &settings) != nil {
			return &DetailError{Err: ErrSecureBrowserExtImport, Detail: fmt.Sprintf(": corrupt extensions.settings in %s", path)}
		}
	}

	for id, entry := range entries {
		settings[id] = entry
	}

	settingsRaw, err := json.Marshal(settings)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	ext["settings"] = settingsRaw

	extRaw, err := json.Marshal(ext)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	root["extensions"] = extRaw

	out, err := json.Marshal(root)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return &SentinelCauseError{Sentinel: ErrSecureBrowserExtImport, Cause: err}
	}
	return nil
}

// copyTree recursively copies a directory tree from src to dst, creating dst
// and its parents. Regular files and subdirectories are copied; symlinks are
// dereferenced as regular files. It is used for extension version dirs and
// LevelDB state directories.
func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst, info.Mode())
	}

	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyTree(s, d); err != nil {
				return err
			}
			continue
		}
		fi, statErr := e.Info()
		if statErr != nil {
			return statErr
		}
		if err := copyFile(s, d, fi.Mode()); err != nil {
			return err
		}
	}
	return nil
}

// copyFile copies a single regular file from src to dst with the given mode.
func copyFile(src, dst string, mode os.FileMode) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := in.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return err
	}
	if _, copyErr := io.Copy(out, in); copyErr != nil {
		return errors.Join(copyErr, out.Close())
	}
	return out.Close()
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
