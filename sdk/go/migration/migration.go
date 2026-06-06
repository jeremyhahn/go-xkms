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

// Package migration is the SDK re-export of the key-backend migration engine
// (pkg/migration). Client binaries import this package instead of pkg/migration.
package migration

import pkgmigration "github.com/jeremyhahn/go-xkms/pkg/migration"

// Re-exported types.
type (
	Migrator        = pkgmigration.Migrator
	MigrateOptions  = pkgmigration.MigrateOptions
	MigrationPlan   = pkgmigration.MigrationPlan
	MigrationResult = pkgmigration.MigrationResult
	KeyFilter       = pkgmigration.KeyFilter
)

// Re-exported constructor.
var NewMigrator = pkgmigration.NewMigrator
