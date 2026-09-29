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

import "errors"

// SecureBrowserService errors.
var (
	// ErrSecureBrowserEmptyURL indicates an empty URL was provided to LaunchBrowser.
	ErrSecureBrowserEmptyURL = errors.New("secure_browser: URL cannot be empty")

	// ErrSecureBrowserEmptyPath indicates an empty browser path was provided.
	ErrSecureBrowserEmptyPath = errors.New("secure_browser: browser path cannot be empty")

	// ErrSecureBrowserInvalidURL indicates the URL provided to
	// LaunchBrowser/LaunchBrowserWithOptions failed launch validation
	// (disallowed scheme, missing host, a leading '-', or a control
	// character). See pkg/urlsafety.ValidateLaunchURL.
	ErrSecureBrowserInvalidURL = errors.New("secure_browser: URL failed launch validation")

	// ErrSecureBrowserUnknownFamily indicates the browser binary could not be
	// classified as Chrome or Firefox family.
	ErrSecureBrowserUnknownFamily = errors.New("secure_browser: unrecognized browser family")

	// ErrSecureBrowserLaunchFailed indicates the browser process failed to start.
	ErrSecureBrowserLaunchFailed = errors.New("secure_browser: failed to launch browser")

	// ErrSecureBrowserCertSync indicates certificate synchronization failed.
	ErrSecureBrowserCertSync = errors.New("secure_browser: certificate sync failed")

	// ErrSecureBrowserNoCerts indicates the trust store contains no certificates.
	ErrSecureBrowserNoCerts = errors.New("secure_browser: no certificates in trust store")

	// ErrSecureBrowserPolicyWrite indicates the Firefox policies.json could not be written.
	ErrSecureBrowserPolicyWrite = errors.New("secure_browser: failed to write Firefox policies")

	// ErrSecureBrowserNSSDB indicates an NSS database operation failed.
	ErrSecureBrowserNSSDB = errors.New("secure_browser: NSS database operation failed")

	// ErrSecureBrowserHashRead indicates the trust hash file could not be read.
	ErrSecureBrowserHashRead = errors.New("secure_browser: failed to read trust hash")

	// ErrSecureBrowserHashWrite indicates the trust hash file could not be written.
	ErrSecureBrowserHashWrite = errors.New("secure_browser: failed to write trust hash")

	// ErrSecureBrowserCertExport indicates a PEM certificate file could not be exported.
	ErrSecureBrowserCertExport = errors.New("secure_browser: failed to export certificate")

	// ErrSecureBrowserInvalidMode indicates an invalid profile mode was specified.
	ErrSecureBrowserInvalidMode = errors.New("secure_browser: invalid profile mode")

	// ErrSecureBrowserHomeDir indicates the user's home directory could not
	// be resolved when locating the shared NSS database (~/.pki/nssdb).
	ErrSecureBrowserHomeDir = errors.New("secure_browser: failed to resolve user home directory")

	// ErrSecureBrowserExtImportUnsupported indicates extension import was
	// requested for an unsupported combination. Extension import only
	// works for Chrome-family browsers in isolated profile mode: shared
	// mode already carries the user's own extensions, and Firefox import
	// is out of scope.
	ErrSecureBrowserExtImportUnsupported = errors.New("secure_browser: extension import is only supported for Chrome in isolated mode")

	// ErrSecureBrowserSourceProfile indicates the source Chrome profile
	// directory does not exist or could not be read.
	ErrSecureBrowserSourceProfile = errors.New("secure_browser: source browser profile not found")

	// ErrSecureBrowserExtImport indicates an extension import operation
	// (copying version dirs, merging Preferences, mirroring state) failed.
	ErrSecureBrowserExtImport = errors.New("secure_browser: extension import failed")
)
