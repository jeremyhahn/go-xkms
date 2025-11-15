// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package versioning provides an adapter interface for key versioning,
// allowing calling applications to implement custom version tracking strategies.
//
// This follows the same pattern as auth and logger adapters - providing
// a clean interface that applications can implement while offering sensible
// defaults for common use cases.
package versioning

import (
	"context"
	"time"
)

// KeyVersion represents a specific version of a key
type KeyVersion struct {
	// Version number (monotonically increasing)
	Version uint64

	// KeyID is the identifier for this key
	KeyID string

	// Created timestamp when this version was created
	Created time.Time

	// RotatedFrom is the previous version (0 if this is the first version)
	RotatedFrom uint64

	// Status indicates if this version is active, deprecated, or revoked
	Status VersionStatus

	// Metadata stores additional version-specific information
	Metadata map[string]interface{}
}

// VersionStatus represents the lifecycle status of a key version
type VersionStatus string

const (
	// VersionStatusActive indicates the version is currently active and can be used
	VersionStatusActive VersionStatus = "active"

	// VersionStatusDeprecated indicates the version should not be used for new operations
	// but can still decrypt/verify existing data
	VersionStatusDeprecated VersionStatus = "deprecated"

	// VersionStatusRevoked indicates the version should not be used at all
	VersionStatusRevoked VersionStatus = "revoked"

	// VersionStatusScheduledRotation indicates the version is active but scheduled for rotation
	VersionStatusScheduledRotation VersionStatus = "scheduled_rotation"
)

// VersioningAdapter provides key version tracking and management.
//
// Applications can implement this interface to provide custom versioning
// strategies (e.g., database-backed, distributed systems, compliance requirements).
type VersioningAdapter interface {
	// CreateVersion creates a new version for the given key
	CreateVersion(ctx context.Context, keyID string, metadata map[string]interface{}) (*KeyVersion, error)

	// GetVersion retrieves a specific version of a key
	GetVersion(ctx context.Context, keyID string, version uint64) (*KeyVersion, error)

	// GetLatestVersion retrieves the latest active version of a key
	GetLatestVersion(ctx context.Context, keyID string) (*KeyVersion, error)

	// ListVersions lists all versions for a given key
	ListVersions(ctx context.Context, keyID string) ([]*KeyVersion, error)

	// UpdateStatus updates the status of a specific version
	UpdateStatus(ctx context.Context, keyID string, version uint64, status VersionStatus) error

	// DeleteVersion removes a specific version
	// Returns error if version is still active
	DeleteVersion(ctx context.Context, keyID string, version uint64) error

	// RotateKey creates a new version and deprecates the old one atomically
	RotateKey(ctx context.Context, keyID string, metadata map[string]interface{}) (*KeyVersion, error)

	// ScheduleRotation schedules a key for rotation at the specified time
	ScheduleRotation(ctx context.Context, keyID string, rotateAt time.Time, metadata map[string]interface{}) error

	// GetRotationSchedule retrieves scheduled rotations
	GetRotationSchedule(ctx context.Context, keyID string) (*time.Time, error)

	// PruneVersions removes versions older than the specified retention period
	// Respects minimum version count to ensure recoverability
	PruneVersions(ctx context.Context, keyID string, retentionPeriod time.Duration, minVersions int) error
}

// VersionQueryOptions provides options for querying versions
type VersionQueryOptions struct {
	// Status filters versions by status
	Status []VersionStatus

	// CreatedAfter filters versions created after this time
	CreatedAfter *time.Time

	// CreatedBefore filters versions created before this time
	CreatedBefore *time.Time

	// Limit limits the number of results
	Limit int

	// Offset skips the first N results
	Offset int
}
