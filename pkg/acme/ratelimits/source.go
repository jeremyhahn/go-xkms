// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ratelimits

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

// increment represents a change to a bucket's TAT.
type increment struct {
	cost time.Duration
	ttl  time.Duration
}

// Source is the interface for rate limit bucket storage.
// Implementations must be safe for concurrent use.
type Source interface {
	// Get retrieves the TAT for a bucket.
	// Returns ErrBucketNotFound if the bucket doesn't exist.
	Get(ctx context.Context, bucketKey string) (time.Time, error)

	// BatchGet retrieves TATs for multiple buckets.
	// Missing buckets are omitted from the result.
	BatchGet(ctx context.Context, bucketKeys []string) (map[string]time.Time, error)

	// BatchSet stores TATs for multiple buckets, overwriting existing values.
	BatchSet(ctx context.Context, buckets map[string]time.Time) error

	// BatchSetNotExisting stores TATs only if the buckets don't exist.
	// Returns a map indicating which keys already existed.
	BatchSetNotExisting(ctx context.Context, buckets map[string]time.Time) (map[string]bool, error)

	// BatchIncrement updates TATs by the specified increments.
	BatchIncrement(ctx context.Context, buckets map[string]increment) error

	// BatchDelete removes the specified buckets.
	BatchDelete(ctx context.Context, bucketKeys []string) error
}

// InMemorySource provides an in-memory implementation of Source.
// It uses sync.Map for lock-free concurrent access.
type InMemorySource struct {
	buckets sync.Map
	count   atomic.Int64
}

// bucketEntry stores a TAT with its expiration time.
type bucketEntry struct {
	tat time.Time
	ttl time.Time
}

// Ensure InMemorySource implements Source.
var _ Source = (*InMemorySource)(nil)

// NewInMemorySource creates a new in-memory source.
func NewInMemorySource() *InMemorySource {
	return &InMemorySource{}
}

// Get retrieves the TAT for a bucket.
func (s *InMemorySource) Get(_ context.Context, bucketKey string) (time.Time, error) {
	val, ok := s.buckets.Load(bucketKey)
	if !ok {
		return time.Time{}, errors.ErrBucketNotFound
	}
	entry := val.(bucketEntry)

	// Check if entry has expired.
	if !entry.ttl.IsZero() && time.Now().After(entry.ttl) {
		s.buckets.Delete(bucketKey)
		s.count.Add(-1)
		return time.Time{}, errors.ErrBucketNotFound
	}

	return entry.tat, nil
}

// BatchGet retrieves TATs for multiple buckets.
func (s *InMemorySource) BatchGet(_ context.Context, bucketKeys []string) (map[string]time.Time, error) {
	result := make(map[string]time.Time, len(bucketKeys))
	now := time.Now()

	for _, key := range bucketKeys {
		val, ok := s.buckets.Load(key)
		if !ok {
			continue
		}
		entry := val.(bucketEntry)

		// Skip expired entries.
		if !entry.ttl.IsZero() && now.After(entry.ttl) {
			s.buckets.Delete(key)
			s.count.Add(-1)
			continue
		}

		result[key] = entry.tat
	}
	return result, nil
}

// BatchSet stores TATs for multiple buckets.
func (s *InMemorySource) BatchSet(_ context.Context, buckets map[string]time.Time) error {
	for key, tat := range buckets {
		_, existed := s.buckets.Swap(key, bucketEntry{tat: tat})
		if !existed {
			s.count.Add(1)
		}
	}
	return nil
}

// BatchSetNotExisting stores TATs only for non-existent buckets.
func (s *InMemorySource) BatchSetNotExisting(_ context.Context, buckets map[string]time.Time) (map[string]bool, error) {
	alreadyExists := make(map[string]bool, len(buckets))
	for key, tat := range buckets {
		_, existed := s.buckets.LoadOrStore(key, bucketEntry{tat: tat})
		if existed {
			alreadyExists[key] = true
		} else {
			s.count.Add(1)
		}
	}
	return alreadyExists, nil
}

// BatchIncrement updates TATs by the specified increments.
func (s *InMemorySource) BatchIncrement(_ context.Context, buckets map[string]increment) error {
	for key, incr := range buckets {
		for {
			val, ok := s.buckets.Load(key)
			if !ok {
				// Bucket doesn't exist, skip.
				break
			}
			entry := val.(bucketEntry)
			newEntry := bucketEntry{
				tat: entry.tat.Add(incr.cost),
				ttl: time.Now().Add(incr.ttl),
			}
			if s.buckets.CompareAndSwap(key, val, newEntry) {
				break
			}
			// CAS failed, retry.
		}
	}
	return nil
}

// BatchDelete removes the specified buckets.
func (s *InMemorySource) BatchDelete(_ context.Context, bucketKeys []string) error {
	for _, key := range bucketKeys {
		if _, existed := s.buckets.LoadAndDelete(key); existed {
			s.count.Add(-1)
		}
	}
	return nil
}

// Count returns the current number of buckets.
func (s *InMemorySource) Count() int64 {
	return s.count.Load()
}

// Cleanup removes expired entries. Call periodically.
func (s *InMemorySource) Cleanup() int {
	now := time.Now()
	removed := 0
	s.buckets.Range(func(key, val any) bool {
		entry := val.(bucketEntry)
		if !entry.ttl.IsZero() && now.After(entry.ttl) {
			if s.buckets.CompareAndDelete(key, val) {
				s.count.Add(-1)
				removed++
			}
		}
		return true
	})
	return removed
}

// StartCleanupRoutine starts a background goroutine to periodically clean up expired entries.
// Returns a cancel function to stop the routine.
func (s *InMemorySource) StartCleanupRoutine(interval time.Duration) func() {
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- cancel is returned to the caller
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
	return cancel
}
