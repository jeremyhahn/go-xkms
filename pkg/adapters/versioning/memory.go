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

package versioning

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryVersioningAdapter provides an in-memory implementation of VersioningAdapter.
// Suitable for development, testing, and single-instance deployments.
// For production multi-instance deployments, implement a database-backed adapter.
type MemoryVersioningAdapter struct {
	versions  map[string][]*KeyVersion // keyID -> list of versions
	schedules map[string]*time.Time    // keyID -> rotation schedule
	mu        sync.RWMutex
}

var _ VersioningAdapter = (*MemoryVersioningAdapter)(nil)

// NewMemoryVersioningAdapter creates a new in-memory versioning adapter
func NewMemoryVersioningAdapter() *MemoryVersioningAdapter {
	return &MemoryVersioningAdapter{
		versions:  make(map[string][]*KeyVersion),
		schedules: make(map[string]*time.Time),
	}
}

// CreateVersion creates a new version for the given key
func (m *MemoryVersioningAdapter) CreateVersion(ctx context.Context, keyID string, metadata map[string]interface{}) (*KeyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get current versions for this key
	versions := m.versions[keyID]

	// Determine new version number
	var version uint64 = 1
	var rotatedFrom uint64 = 0

	if len(versions) > 0 {
		// Find highest version number
		for _, v := range versions {
			if v.Version >= version {
				version = v.Version + 1
			}
		}
		// The previous active version
		for _, v := range versions {
			if v.Status == VersionStatusActive {
				rotatedFrom = v.Version
				break
			}
		}
	}

	newVersion := &KeyVersion{
		Version:     version,
		KeyID:       keyID,
		Created:     time.Now().UTC(),
		RotatedFrom: rotatedFrom,
		Status:      VersionStatusActive,
		Metadata:    metadata,
	}

	m.versions[keyID] = append(m.versions[keyID], newVersion)

	return newVersion, nil
}

// GetVersion retrieves a specific version of a key
func (m *MemoryVersioningAdapter) GetVersion(ctx context.Context, keyID string, version uint64) (*KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := m.versions[keyID]
	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}

	return nil, fmt.Errorf("version %d not found for key %s", version, keyID)
}

// GetLatestVersion retrieves the latest active version of a key
func (m *MemoryVersioningAdapter) GetLatestVersion(ctx context.Context, keyID string) (*KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := m.versions[keyID]
	if len(versions) == 0 {
		return nil, fmt.Errorf("no versions found for key %s", keyID)
	}

	// Find the latest active version
	var latest *KeyVersion
	for _, v := range versions {
		if v.Status == VersionStatusActive {
			if latest == nil || v.Version > latest.Version {
				latest = v
			}
		}
	}

	if latest == nil {
		return nil, fmt.Errorf("no active version found for key %s", keyID)
	}

	return latest, nil
}

// ListVersions lists all versions for a given key
func (m *MemoryVersioningAdapter) ListVersions(ctx context.Context, keyID string) ([]*KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	versions := m.versions[keyID]
	if len(versions) == 0 {
		return []*KeyVersion{}, nil
	}

	// Return a copy to prevent external modification
	result := make([]*KeyVersion, len(versions))
	copy(result, versions)

	return result, nil
}

// UpdateStatus updates the status of a specific version
func (m *MemoryVersioningAdapter) UpdateStatus(ctx context.Context, keyID string, version uint64, status VersionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	versions := m.versions[keyID]
	for _, v := range versions {
		if v.Version == version {
			v.Status = status
			return nil
		}
	}

	return fmt.Errorf("version %d not found for key %s", version, keyID)
}

// DeleteVersion removes a specific version
func (m *MemoryVersioningAdapter) DeleteVersion(ctx context.Context, keyID string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	versions := m.versions[keyID]
	for i, v := range versions {
		if v.Version == version {
			if v.Status == VersionStatusActive {
				return fmt.Errorf("cannot delete active version %d for key %s", version, keyID)
			}

			// Remove from slice
			m.versions[keyID] = append(versions[:i], versions[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("version %d not found for key %s", version, keyID)
}

// RotateKey creates a new version and deprecates the old one atomically
func (m *MemoryVersioningAdapter) RotateKey(ctx context.Context, keyID string, metadata map[string]interface{}) (*KeyVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Deprecate all currently active versions
	versions := m.versions[keyID]
	for _, v := range versions {
		if v.Status == VersionStatusActive {
			v.Status = VersionStatusDeprecated
		}
	}

	// Create new version
	var version uint64 = 1
	var rotatedFrom uint64 = 0

	if len(versions) > 0 {
		for _, v := range versions {
			if v.Version >= version {
				version = v.Version + 1
			}
		}
		// Find the previously active version
		for _, v := range versions {
			if v.Status == VersionStatusDeprecated && v.Version == version-1 {
				rotatedFrom = v.Version
				break
			}
		}
	}

	newVersion := &KeyVersion{
		Version:     version,
		KeyID:       keyID,
		Created:     time.Now().UTC(),
		RotatedFrom: rotatedFrom,
		Status:      VersionStatusActive,
		Metadata:    metadata,
	}

	m.versions[keyID] = append(m.versions[keyID], newVersion)

	return newVersion, nil
}

// ScheduleRotation schedules a key for rotation at the specified time
func (m *MemoryVersioningAdapter) ScheduleRotation(ctx context.Context, keyID string, rotateAt time.Time, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.schedules[keyID] = &rotateAt

	// Update the latest version status to indicate scheduled rotation
	versions := m.versions[keyID]
	for _, v := range versions {
		if v.Status == VersionStatusActive {
			v.Status = VersionStatusScheduledRotation
			break
		}
	}

	return nil
}

// GetRotationSchedule retrieves scheduled rotations
func (m *MemoryVersioningAdapter) GetRotationSchedule(ctx context.Context, keyID string) (*time.Time, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	schedule, exists := m.schedules[keyID]
	if !exists {
		return nil, nil
	}

	return schedule, nil
}

// PruneVersions removes versions older than the specified retention period
func (m *MemoryVersioningAdapter) PruneVersions(ctx context.Context, keyID string, retentionPeriod time.Duration, minVersions int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	versions := m.versions[keyID]
	if len(versions) <= minVersions {
		// Don't prune if we'd go below minimum
		return nil
	}

	cutoff := time.Now().UTC().Add(-retentionPeriod)
	var kept []*KeyVersion
	var prunable []*KeyVersion

	// First pass: separate active/new from old/deprecated
	for _, v := range versions {
		// Always keep active versions and those newer than retention period
		if v.Status == VersionStatusActive || v.Created.After(cutoff) {
			kept = append(kept, v)
		} else {
			prunable = append(prunable, v)
		}
	}

	// Second pass: keep enough prunable versions to reach minVersions
	needed := minVersions - len(kept)
	if needed > 0 && needed <= len(prunable) {
		// Keep the newest 'needed' from prunable
		kept = append(kept, prunable[len(prunable)-needed:]...)
	} else if needed > 0 {
		// Keep all prunable if we need them to reach minVersions
		kept = append(kept, prunable...)
	}

	m.versions[keyID] = kept

	return nil
}
