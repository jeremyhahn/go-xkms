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

// Package bootstrap is the SDK re-export of the canonical trust-bootstrap
// dispatch (pkg/trust/bootstrap: DANE / Noise / SPKI / Direct / Auto). Client
// binaries import this package instead of pkg/trust/bootstrap.
package bootstrap

import pkgbootstrap "github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"

// Re-exported types.
type (
	Config       = pkgbootstrap.Config
	Mode         = pkgbootstrap.Mode
	CABundle     = pkgbootstrap.CABundle
	DANEConfig   = pkgbootstrap.DANEConfig
	NoiseConfig  = pkgbootstrap.NoiseConfig
	SPKIConfig   = pkgbootstrap.SPKIConfig
	DirectConfig = pkgbootstrap.DirectConfig
)

// Re-exported mode constants.
const (
	ModeAuto   = pkgbootstrap.ModeAuto
	ModeDANE   = pkgbootstrap.ModeDANE
	ModeNoise  = pkgbootstrap.ModeNoise
	ModeSPKI   = pkgbootstrap.ModeSPKI
	ModeDirect = pkgbootstrap.ModeDirect
)

// Re-exported dispatch entry point.
var Fetch = pkgbootstrap.Fetch
