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

// Package gui re-exports the Trusted CA desktop GUI hosts so command-line
// front ends (xkmsctl) reach them through sdk/go rather than pkg/*.
//
// The package is separate from sdk/go/acme because the GUI hosts consume
// sdk/go/acme's Client: re-exporting them there would form an import cycle.
package gui

import (
	admingui "github.com/jeremyhahn/go-xkms/pkg/acme/gui/admin"
	"github.com/jeremyhahn/go-xkms/pkg/acme/gui/webui"
)

// AdminGUIConfig defines configuration for the admin desktop GUI application.
type AdminGUIConfig = admingui.GUIConfig

// DefaultAdminGUIConfig returns an AdminGUIConfig with sensible defaults.
var DefaultAdminGUIConfig = admingui.DefaultGUIConfig

// AdminAssets provides the embedded admin frontend assets the admin GUI
// serves.
var AdminAssets = webui.AdminAssets
