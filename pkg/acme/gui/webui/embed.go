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

package webui

import (
	adminfe "github.com/jeremyhahn/go-xkms/pkg/acme/web/packages/admin"
	clientfe "github.com/jeremyhahn/go-xkms/pkg/acme/web/packages/client"
)

// AdminAssets provides the embedded admin frontend assets.
var AdminAssets = adminfe.Assets

// ClientAssets provides the embedded ACME client frontend assets.
//
// It exists for the same reason AdminAssets does: the frontend packages are
// generated Go files sitting next to a build output directory, and naming them
// in exactly one place is what stops a consumer holding a stale import path
// when they move. One did -- cmd/acme-client imported
// go-xkms/web/packages/client behind the `gui` build tag, a path that has not
// existed since the frontends moved under pkg/acme/web. Nothing noticed,
// because no build and no `go mod tidy` ever evaluated that tag (#48).
var ClientAssets = clientfe.Assets
