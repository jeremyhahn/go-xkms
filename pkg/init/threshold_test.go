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

package initialize

import (
	"context"
	"errors"
	"testing"
)

// Compile-time interface satisfaction check.
var _ ThresholdInitializer = (*NoopThresholdInitializer)(nil)

func TestNoopThresholdInitializer_InitializeThreshold(t *testing.T) {
	noop := NewNoopThresholdInitializer()
	err := noop.InitializeThreshold(context.Background(), &ThresholdOptions{
		Threshold: 2,
		Total:     3,
		SOPIN:     "123456",
	})
	if !errors.Is(err, ErrThresholdNotSupported) {
		t.Errorf("InitializeThreshold() error = %v, want %v", err, ErrThresholdNotSupported)
	}
}
