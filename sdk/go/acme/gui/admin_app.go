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

//go:build gui

package gui

import (
	admingui "github.com/jeremyhahn/go-xkms/pkg/acme/gui/admin"
)

// AdminApp is the Wails desktop application for the Trusted CA admin GUI.
type AdminApp = admingui.App

// NewAdminApp creates a new admin GUI application.
var NewAdminApp = admingui.NewApp
