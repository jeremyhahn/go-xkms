// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package compose builds xkms's store-backed subsystems — the Password
// Manager (pkg/staticpw), the platform sealed-secret store, the backend
// credential service, SSH (pkg/ssh), the Certificate Authority (pkg/ca) and
// PCR policies (pkg/seal/policy) — from the dependencies a process supplies,
// and wires them into an *xkms.XKMSService.
//
// It is the single construction path for those subsystems. xkmsd
// (pkg/server) calls the per-feature Build* functions at the points of its
// own start-up sequence; an embedding host reaches the same functions
// through Build, which pkg/apimodule runs when a host mounts go-xkms's
// ServiceModule. Both then publish the result with Stores.Wire, so a host
// and xkmsd compose every store the same way.
//
// A feature whose dependency is missing stays off. Build records one typed
// *FeatureDisabledError per feature it leaves off (and a *FeatureBuildError
// per feature whose construction failed) in Stores.Disabled and logs each,
// so an absent feature is always explained and never silent.
package compose
