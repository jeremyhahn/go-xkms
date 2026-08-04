// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package errs

import (
	"errors"
	"fmt"
	"testing"
)

var errSentinel = errors.New("sentinel failure")

func TestMessageError(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{name: "static message", msg: "config is nil"},
		{name: "formatted message", msg: fmt.Sprintf("unsupported algorithm %q", "RS1")},
		{name: "empty message", msg: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &Message{Msg: tt.msg}
			if got := err.Error(); got != tt.msg {
				t.Fatalf("Error() = %q, want %q", got, tt.msg)
			}
			if errors.Unwrap(err) != nil {
				t.Fatalf("Message must not unwrap to a cause")
			}
		})
	}
}

func TestWrappedError(t *testing.T) {
	err := &Wrapped{Msg: "failed to open session", Err: errSentinel}
	want := fmt.Errorf("failed to open session: %w", errSentinel).Error()
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, errSentinel) {
		t.Fatal("errors.Is must reach the wrapped cause")
	}
}

func TestWrappedErrorNestedChain(t *testing.T) {
	inner := &Wrapped{Msg: "read key", Err: errSentinel}
	outer := &Wrapped{Msg: "load backend", Err: inner}
	if got, want := outer.Error(), "load backend: read key: sentinel failure"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(outer, errSentinel) {
		t.Fatal("errors.Is must traverse nested Wrapped chain")
	}
	var w *Wrapped
	if !errors.As(outer, &w) {
		t.Fatal("errors.As must match *Wrapped")
	}
}

func TestDetailError(t *testing.T) {
	err := &Detail{Err: errSentinel, Detail: "slot 3 unavailable"}
	want := fmt.Errorf("%w: %s", errSentinel, "slot 3 unavailable").Error()
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, errSentinel) {
		t.Fatal("errors.Is must match the sentinel")
	}
}

func TestDetailErrorDoesNotWrapDetailText(t *testing.T) {
	other := errors.New("other")
	err := &Detail{Err: errSentinel, Detail: other.Error()}
	if errors.Is(err, other) {
		t.Fatal("detail text must not participate in the unwrap chain")
	}
}

func TestAffixError(t *testing.T) {
	err := &Affix{Prefix: "nonce reuse detected: ", Err: errSentinel, Suffix: " (CRITICAL SECURITY VIOLATION)"}
	want := fmt.Errorf("nonce reuse detected: %w (CRITICAL SECURITY VIOLATION)", errSentinel).Error()
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, errSentinel) {
		t.Fatal("errors.Is must reach the wrapped cause")
	}
}

func TestAffixErrorEmptyAffixes(t *testing.T) {
	err := &Affix{Err: errSentinel}
	if got := err.Error(); got != errSentinel.Error() {
		t.Fatalf("Error() = %q, want %q", got, errSentinel.Error())
	}
}

func TestJoinedError(t *testing.T) {
	cause := errors.New("cause failure")
	tests := []struct {
		name   string
		detail string
		want   string
	}{
		{
			name: "no detail",
			want: fmt.Errorf("%w: %w", errSentinel, cause).Error(),
		},
		{
			name:   "with detail",
			detail: "failed to parse creation options",
			want:   fmt.Errorf("%w: failed to parse creation options: %w", errSentinel, cause).Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &Joined{Lead: errSentinel, Detail: tt.detail, Cause: cause}
			if got := err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
			if !errors.Is(err, errSentinel) {
				t.Fatal("errors.Is must match the lead error")
			}
			if !errors.Is(err, cause) {
				t.Fatal("errors.Is must match the cause error")
			}
		})
	}
}
