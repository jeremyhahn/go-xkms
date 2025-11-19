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
	"testing"
	"time"
)

func TestMemoryVersioningAdapter_CreateVersion(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	metadata := map[string]interface{}{
		"algorithm": "RSA",
		"key_size":  2048,
	}

	// Create first version
	v1, err := adapter.CreateVersion(ctx, "test-key", metadata)
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	if v1.Version != 1 {
		t.Errorf("Expected version 1, got %d", v1.Version)
	}

	if v1.Status != VersionStatusActive {
		t.Errorf("Expected status active, got %s", v1.Status)
	}

	if v1.RotatedFrom != 0 {
		t.Errorf("Expected rotatedFrom 0, got %d", v1.RotatedFrom)
	}

	// Create second version
	v2, err := adapter.CreateVersion(ctx, "test-key", metadata)
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	if v2.Version != 2 {
		t.Errorf("Expected version 2, got %d", v2.Version)
	}
}

func TestMemoryVersioningAdapter_GetVersion(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	// Create a version
	v1, err := adapter.CreateVersion(ctx, "test-key", nil)
	if err != nil {
		t.Fatalf("Failed to create version: %v", err)
	}

	// Retrieve it
	retrieved, err := adapter.GetVersion(ctx, "test-key", v1.Version)
	if err != nil {
		t.Fatalf("Failed to get version: %v", err)
	}

	if retrieved.Version != v1.Version {
		t.Errorf("Expected version %d, got %d", v1.Version, retrieved.Version)
	}

	// Try to get non-existent version
	_, err = adapter.GetVersion(ctx, "test-key", 999)
	if err == nil {
		t.Error("Expected error for non-existent version, got nil")
	}
}

func TestMemoryVersioningAdapter_GetLatestVersion(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	// No versions yet
	_, err := adapter.GetLatestVersion(ctx, "test-key")
	if err == nil {
		t.Error("Expected error for no versions, got nil")
	}

	// Create multiple versions
	v1, _ := adapter.CreateVersion(ctx, "test-key", nil)
	v2, _ := adapter.CreateVersion(ctx, "test-key", nil)

	// Deprecate v1
	_ = adapter.UpdateStatus(ctx, "test-key", v1.Version, VersionStatusDeprecated)

	// Latest should be v2
	latest, err := adapter.GetLatestVersion(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to get latest version: %v", err)
	}

	if latest.Version != v2.Version {
		t.Errorf("Expected version %d, got %d", v2.Version, latest.Version)
	}
}

func TestMemoryVersioningAdapter_ListVersions(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	// Empty list
	versions, err := adapter.ListVersions(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to list versions: %v", err)
	}

	if len(versions) != 0 {
		t.Errorf("Expected 0 versions, got %d", len(versions))
	}

	// Create some versions
	_, _ = adapter.CreateVersion(ctx, "test-key", nil)
	_, _ = adapter.CreateVersion(ctx, "test-key", nil)
	_, _ = adapter.CreateVersion(ctx, "test-key", nil)

	versions, err = adapter.ListVersions(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to list versions: %v", err)
	}

	if len(versions) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(versions))
	}
}

func TestMemoryVersioningAdapter_UpdateStatus(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	v1, _ := adapter.CreateVersion(ctx, "test-key", nil)

	// Update status
	err := adapter.UpdateStatus(ctx, "test-key", v1.Version, VersionStatusDeprecated)
	if err != nil {
		t.Fatalf("Failed to update status: %v", err)
	}

	// Verify status changed
	retrieved, _ := adapter.GetVersion(ctx, "test-key", v1.Version)
	if retrieved.Status != VersionStatusDeprecated {
		t.Errorf("Expected status deprecated, got %s", retrieved.Status)
	}

	// Try to update non-existent version
	err = adapter.UpdateStatus(ctx, "test-key", 999, VersionStatusRevoked)
	if err == nil {
		t.Error("Expected error for non-existent version, got nil")
	}
}

func TestMemoryVersioningAdapter_DeleteVersion(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	v1, _ := adapter.CreateVersion(ctx, "test-key", nil)

	// Cannot delete active version
	err := adapter.DeleteVersion(ctx, "test-key", v1.Version)
	if err == nil {
		t.Error("Expected error when deleting active version, got nil")
	}

	// Deprecate first
	_ = adapter.UpdateStatus(ctx, "test-key", v1.Version, VersionStatusDeprecated)

	// Now delete should work
	err = adapter.DeleteVersion(ctx, "test-key", v1.Version)
	if err != nil {
		t.Fatalf("Failed to delete version: %v", err)
	}

	// Verify deleted
	_, err = adapter.GetVersion(ctx, "test-key", v1.Version)
	if err == nil {
		t.Error("Expected error for deleted version, got nil")
	}
}

func TestMemoryVersioningAdapter_RotateKey(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	// Create initial version
	v1, _ := adapter.CreateVersion(ctx, "test-key", nil)

	// Rotate
	v2, err := adapter.RotateKey(ctx, "test-key", map[string]interface{}{"rotated": true})
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify v2 is active
	if v2.Status != VersionStatusActive {
		t.Errorf("Expected v2 status active, got %s", v2.Status)
	}

	// Verify v1 is deprecated
	v1Updated, _ := adapter.GetVersion(ctx, "test-key", v1.Version)
	if v1Updated.Status != VersionStatusDeprecated {
		t.Errorf("Expected v1 status deprecated, got %s", v1Updated.Status)
	}

	// Verify v2 points to v1
	if v2.RotatedFrom != v1.Version {
		t.Errorf("Expected v2 rotatedFrom %d, got %d", v1.Version, v2.RotatedFrom)
	}
}

func TestMemoryVersioningAdapter_ScheduleRotation(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	v1, _ := adapter.CreateVersion(ctx, "test-key", nil)

	rotateAt := time.Now().Add(24 * time.Hour)
	err := adapter.ScheduleRotation(ctx, "test-key", rotateAt, nil)
	if err != nil {
		t.Fatalf("Failed to schedule rotation: %v", err)
	}

	// Verify schedule
	schedule, err := adapter.GetRotationSchedule(ctx, "test-key")
	if err != nil {
		t.Fatalf("Failed to get rotation schedule: %v", err)
	}

	if schedule == nil {
		t.Fatal("Expected schedule, got nil")
	}

	if !schedule.Equal(rotateAt) {
		t.Errorf("Expected schedule %v, got %v", rotateAt, *schedule)
	}

	// Verify version status updated
	v1Updated, _ := adapter.GetVersion(ctx, "test-key", v1.Version)
	if v1Updated.Status != VersionStatusScheduledRotation {
		t.Errorf("Expected status scheduled_rotation, got %s", v1Updated.Status)
	}
}

func TestMemoryVersioningAdapter_PruneVersions(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	// Create versions with different ages
	v1, _ := adapter.CreateVersion(ctx, "test-key", nil)
	time.Sleep(10 * time.Millisecond)

	v2, _ := adapter.CreateVersion(ctx, "test-key", nil)
	time.Sleep(10 * time.Millisecond)

	v3, _ := adapter.CreateVersion(ctx, "test-key", nil)

	// Deprecate old versions
	_ = adapter.UpdateStatus(ctx, "test-key", v1.Version, VersionStatusDeprecated)
	_ = adapter.UpdateStatus(ctx, "test-key", v2.Version, VersionStatusDeprecated)

	// Prune with retention period of 0 (should keep only minVersions)
	err := adapter.PruneVersions(ctx, "test-key", 0, 2)
	if err != nil {
		t.Fatalf("Failed to prune versions: %v", err)
	}

	// Should have exactly 2 versions left
	versions, _ := adapter.ListVersions(ctx, "test-key")
	if len(versions) != 2 {
		t.Errorf("Expected 2 versions after pruning, got %d", len(versions))
	}

	// Active version should never be pruned
	found := false
	for _, v := range versions {
		if v.Version == v3.Version {
			found = true
			break
		}
	}
	if !found {
		t.Error("Active version was pruned!")
	}
}

func TestMemoryVersioningAdapter_ConcurrentAccess(t *testing.T) {
	adapter := NewMemoryVersioningAdapter()
	ctx := context.Background()

	// Test concurrent creates
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, _ = adapter.CreateVersion(ctx, "test-key", nil)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	versions, _ := adapter.ListVersions(ctx, "test-key")
	if len(versions) != 10 {
		t.Errorf("Expected 10 versions from concurrent creates, got %d", len(versions))
	}
}
