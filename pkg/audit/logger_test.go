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

package audit

import (
	"context"
	"testing"
)

func TestNoOpLogger_Log(t *testing.T) {
	logger := &NoOpLogger{}

	t.Run("Success", func(t *testing.T) {
		err := logger.Log(context.Background(), &Event{
			Subject:    "user@example.com",
			Action:     "key.generate",
			Resource:   "keys",
			ResourceID: "key-123",
			Outcome:    OutcomeAllow,
		})
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("NilEvent", func(t *testing.T) {
		err := logger.Log(context.Background(), nil)
		if err != nil {
			t.Fatalf("expected nil error from NoOpLogger even with nil event, got: %v", err)
		}
	})
}

func TestNoOpLogger_Close(t *testing.T) {
	logger := &NoOpLogger{}

	t.Run("Success", func(t *testing.T) {
		err := logger.Close()
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("Idempotent", func(t *testing.T) {
		if err := logger.Close(); err != nil {
			t.Fatalf("first close: expected nil error, got: %v", err)
		}
		if err := logger.Close(); err != nil {
			t.Fatalf("second close: expected nil error, got: %v", err)
		}
	})
}

func TestNoOpLogger_InterfaceCompliance(t *testing.T) {
	var _ Logger = (*NoOpLogger)(nil)
}
