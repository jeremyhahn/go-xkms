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
)
