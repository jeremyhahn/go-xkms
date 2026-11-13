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

package ca

import "github.com/jeremyhahn/go-xkms/pkg/certsubject"

// StampTenant is certsubject.StampTenant: the one place an issued
// certificate gets its tenant as Subject.OrganizationalUnit[0]. It lives in
// the leaf package pkg/certsubject so that packages pkg/ca imports, such as
// pkg/xkms, stamp their own certificates with the same function.
var StampTenant = certsubject.StampTenant
