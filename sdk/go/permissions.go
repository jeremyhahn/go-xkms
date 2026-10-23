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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/auth"

// Trust write permission, re-exported so a consumer that serves the trust
// write verbs (go-quicbaas's POST /api/v1/trust/publish-dane and
// /api/v1/trust/auto-import-aia) gates them with go-xkms's names without
// importing pkg/auth. The service module registers both permissions,
// cross-scoped, and grants them to Admin (and so Owner).
const (
	// PermissionResourceTrust is the trust write resource ("trust").
	PermissionResourceTrust = auth.ResourceTrust

	// PermissionActionPublishDANE publishes the CA's DANE TLSA records
	// ("publish_dane").
	PermissionActionPublishDANE = auth.ActionPublishDANE

	// PermissionActionAutoImportAIA imports an issuer CA from an AIA
	// caIssuers URL ("auto_import_aia").
	PermissionActionAutoImportAIA = auth.ActionAutoImportAIA
)
