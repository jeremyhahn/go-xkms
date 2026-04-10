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

package services

import "errors"

// BrowserService errors.
var (
	// ErrBrowserEmptyURL indicates an empty URL was provided to OpenURL.
	ErrBrowserEmptyURL = errors.New("browser_service: URL cannot be empty")

	// ErrBrowserLaunchFailed indicates the browser process failed to start.
	ErrBrowserLaunchFailed = errors.New("browser_service: failed to launch browser")

	// ErrBrowserInvalidConfig indicates the browser configuration is invalid.
	ErrBrowserInvalidConfig = errors.New("browser_service: invalid configuration")

	// ErrBrowserConfigSave indicates the configuration could not be persisted.
	ErrBrowserConfigSave = errors.New("browser_service: failed to save configuration")

	// ErrBrowserConfigLoad indicates the configuration could not be loaded.
	ErrBrowserConfigLoad = errors.New("browser_service: failed to load configuration")

	// ErrBrowserTrustBundleExport indicates the browser trust bundle could not be exported.
	ErrBrowserTrustBundleExport = errors.New("browser_service: trust bundle export failed")
)
