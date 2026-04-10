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

package handlers

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestValidateTokenData(t *testing.T) {
	tests := []struct {
		name    string
		data    *TokenData
		wantErr error
	}{
		{
			name:    "nil data",
			data:    nil,
			wantErr: ErrNilTokenResponse,
		},
		{
			name:    "valid data",
			data:    &TokenData{AccessToken: "test"},
			wantErr: nil,
		},
		{
			name:    "empty data",
			data:    &TokenData{},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTokenData(tt.data)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateTokenData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNoopHandler(t *testing.T) {
	handler := NewNoopHandler()

	if handler.Name() != "noop" {
		t.Errorf("Name() = %s, want noop", handler.Name())
	}

	// Should handle successfully
	err := handler.Handle(context.Background(), &TokenData{AccessToken: "test"})
	if err != nil {
		t.Errorf("Handle() error = %v, want nil", err)
	}

	// Should handle nil data (noop doesn't validate)
	err = handler.Handle(context.Background(), nil)
	if err != nil {
		t.Errorf("Handle() with nil error = %v, want nil", err)
	}
}

func TestChainHandler(t *testing.T) {
	t.Run("empty chain", func(t *testing.T) {
		chain := NewChainHandler()
		err := chain.Handle(context.Background(), &TokenData{})
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}
	})

	t.Run("single handler", func(t *testing.T) {
		called := false
		handler := &testHandler{
			fn: func(ctx context.Context, data *TokenData) error {
				called = true
				return nil
			},
		}

		chain := NewChainHandler(handler)
		err := chain.Handle(context.Background(), &TokenData{})

		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}
		if !called {
			t.Error("Handler was not called")
		}
	})

	t.Run("multiple handlers in order", func(t *testing.T) {
		order := []int{}

		h1 := &testHandler{
			fn: func(ctx context.Context, data *TokenData) error {
				order = append(order, 1)
				return nil
			},
		}
		h2 := &testHandler{
			fn: func(ctx context.Context, data *TokenData) error {
				order = append(order, 2)
				return nil
			},
		}
		h3 := &testHandler{
			fn: func(ctx context.Context, data *TokenData) error {
				order = append(order, 3)
				return nil
			},
		}

		chain := NewChainHandler(h1, h2, h3)
		err := chain.Handle(context.Background(), &TokenData{})

		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}
		if len(order) != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3 {
			t.Errorf("Handlers called in wrong order: %v", order)
		}
	})

	t.Run("stops on error", func(t *testing.T) {
		testErr := errors.New("test error")
		h2Called := false

		h1 := &testHandler{
			fn: func(ctx context.Context, data *TokenData) error {
				return testErr
			},
		}
		h2 := &testHandler{
			fn: func(ctx context.Context, data *TokenData) error {
				h2Called = true
				return nil
			},
		}

		chain := NewChainHandler(h1, h2)
		err := chain.Handle(context.Background(), &TokenData{})

		if err != testErr {
			t.Errorf("Handle() error = %v, want %v", err, testErr)
		}
		if h2Called {
			t.Error("Second handler should not be called after error")
		}
	})

	t.Run("add handler", func(t *testing.T) {
		chain := NewChainHandler()
		chain.Add(NewNoopHandler())

		if chain.Name() != "chain" {
			t.Errorf("Name() = %s, want chain", chain.Name())
		}

		err := chain.Handle(context.Background(), &TokenData{})
		if err != nil {
			t.Errorf("Handle() error = %v, want nil", err)
		}
	})
}

func TestTokenData(t *testing.T) {
	now := time.Now()
	data := &TokenData{
		AccessToken:  "access123",
		RefreshToken: "refresh456",
		IDToken:      "id789",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		Expiry:       now.Add(time.Hour),
		Scope:        "openid profile",
		AWSCredentials: &AWSCredentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "session-token-123",
			Expiration:      now.Add(time.Hour),
			Region:          "us-east-1",
		},
		Extra: map[string]interface{}{
			"custom_field": "custom_value",
		},
	}

	if data.AccessToken != "access123" {
		t.Errorf("AccessToken = %s, want access123", data.AccessToken)
	}
	if data.AWSCredentials.Region != "us-east-1" {
		t.Errorf("Region = %s, want us-east-1", data.AWSCredentials.Region)
	}
}

// testHandler is a simple handler for testing.
type testHandler struct {
	fn func(ctx context.Context, data *TokenData) error
}

func (h *testHandler) Handle(ctx context.Context, data *TokenData) error {
	if h.fn != nil {
		return h.fn(ctx, data)
	}
	return nil
}

func (h *testHandler) Name() string {
	return "test"
}
