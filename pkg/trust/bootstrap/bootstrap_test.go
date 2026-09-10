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

package bootstrap

import (
	"context"
	"errors"
	"testing"
)

// =============================================================================
// Mode dispatch
// =============================================================================

func TestFetch_UnsetModeErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{})
	if !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("expected ErrInvalidMode for empty mode; got %v", err)
	}
}

func TestFetch_UnknownModeErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{Mode: "synesthesia"})
	if !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("expected ErrInvalidMode for unknown mode; got %v", err)
	}
}

// =============================================================================
// Per-mode validation (no network)
// =============================================================================

func TestFetch_DANEWithoutSubConfigErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeDANE,
		ServerURL: "https://kms.example.com:8443",
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured for DANE without DANEConfig; got %v", err)
	}
}

func TestFetch_DANEWithoutServerURLErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode: ModeDANE,
		DANE: &DANEConfig{Hostname: "kms.example.com"},
	})
	if !errors.Is(err, ErrServerURLRequired) {
		t.Fatalf("expected ErrServerURLRequired for DANE without ServerURL; got %v", err)
	}
}

func TestFetch_NoiseWithoutSubConfigErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeNoise,
		ServerURL: "https://kms.example.com:8443",
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured for Noise without NoiseConfig; got %v", err)
	}
}

func TestFetch_NoiseWithoutServerAddrOrURLErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:  ModeNoise,
		Noise: &NoiseConfig{ServerStaticKey: "abc"},
		// no ServerURL, no ServerAddr → no address can be derived
	})
	if !errors.Is(err, ErrServerURLRequired) {
		t.Fatalf("expected ErrServerURLRequired for Noise without address; got %v", err)
	}
}

func TestFetch_SPKIWithoutSubConfigErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeSPKI,
		ServerURL: "https://kms.example.com:8443",
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured for SPKI without SPKIConfig; got %v", err)
	}
}

func TestFetch_SPKIWithoutServerURLErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode: ModeSPKI,
		SPKI: &SPKIConfig{Pin: "abc"},
	})
	if !errors.Is(err, ErrServerURLRequired) {
		t.Fatalf("expected ErrServerURLRequired for SPKI without ServerURL; got %v", err)
	}
}

func TestFetch_DirectWithoutSubConfigErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeDirect,
		ServerURL: "https://kms.example.com:8443",
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured for Direct without DirectConfig; got %v", err)
	}
}

func TestFetch_DirectWithoutServerURLErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:   ModeDirect,
		Direct: &DirectConfig{},
	})
	if !errors.Is(err, ErrServerURLRequired) {
		t.Fatalf("expected ErrServerURLRequired for Direct without ServerURL; got %v", err)
	}
}

// =============================================================================
// Auto mode dispatch
// =============================================================================

func TestFetch_AutoWithoutAnyConfigErrors(t *testing.T) {
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeAuto,
		ServerURL: "https://kms.example.com:8443",
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured for Auto without any sub-configs; got %v", err)
	}
}

func TestFetch_AutoIgnoresUnconfiguredModes(t *testing.T) {
	// Auto with ONLY noise configured (and no key set) should still
	// report ErrModeNotConfigured because the noise sub-config is
	// effectively empty (ServerStaticKey == "").
	_, err := Fetch(context.Background(), Config{
		Mode:      ModeAuto,
		ServerURL: "https://kms.example.com:8443",
		Noise:     &NoiseConfig{}, // empty key → ignored
	})
	if !errors.Is(err, ErrModeNotConfigured) {
		t.Fatalf("expected ErrModeNotConfigured when no usable methods configured; got %v", err)
	}
}

// =============================================================================
// DeriveNoiseAddr
// =============================================================================

func TestDeriveNoiseAddr(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"empty input":                            {in: "", want: ""},
		"https with port":                        {in: "https://kms.example.com:8443", want: "kms.example.com:" + DefaultNoisePort},
		"https without port":                     {in: "https://kms.example.com", want: "kms.example.com:" + DefaultNoisePort},
		"http with port":                         {in: "http://kms.example.com:80", want: "kms.example.com:" + DefaultNoisePort},
		"bare host with port":                    {in: "kms.example.com:8443", want: "kms.example.com:" + DefaultNoisePort},
		"bare host no port":                      {in: "kms.example.com", want: "kms.example.com:" + DefaultNoisePort},
		"with path":                              {in: "https://kms.example.com:8443/api/v1", want: "kms.example.com:" + DefaultNoisePort},
		"ipv4":                                   {in: "https://10.0.0.5:8443", want: "10.0.0.5:" + DefaultNoisePort},
		"ipv6 with port":                         {in: "https://[fd00::1]:8443", want: "[fd00::1]:" + DefaultNoisePort},
		"ipv6 without port":                      {in: "https://[fd00::1]", want: "[fd00::1]:" + DefaultNoisePort},
		"bare ipv6 with port":                    {in: "[fd00::1]:8443", want: "[fd00::1]:" + DefaultNoisePort},
		"bare ipv6 unbracketed":                  {in: "fd00::1", want: "[fd00::1]:" + DefaultNoisePort},
		"bare ipv6 unbracketed non-numeric tail": {in: "fd00::a", want: "[fd00::a]:" + DefaultNoisePort},
		"bare ipv6 bracketed no port":            {in: "[fd00::1]", want: "[fd00::1]:" + DefaultNoisePort},
		"bare ipv4":                              {in: "10.0.0.5", want: "10.0.0.5:" + DefaultNoisePort},
		"ipv6 with path":                         {in: "https://[fd00::1]/api/v1", want: "[fd00::1]:" + DefaultNoisePort},
		"userinfo dropped":                       {in: "https://admin@kms.example.com:8443", want: "kms.example.com:" + DefaultNoisePort},
		"no host":                                {in: "https:///api", want: ""},
		"scheme only":                            {in: "https://", want: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := DeriveNoiseAddr(tc.in); got != tc.want {
				t.Fatalf("DeriveNoiseAddr(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// =============================================================================
// FetchError
// =============================================================================

func TestFetchError_IsAndUnwrap(t *testing.T) {
	cause := errors.New("network down")
	e := &FetchError{Mode: ModeDANE, Cause: cause}
	if !errors.Is(e, ErrFetch) {
		t.Fatal("FetchError must satisfy errors.Is(ErrFetch)")
	}
	if !errors.Is(e, cause) {
		t.Fatal("FetchError must unwrap to its cause")
	}
	if got := e.Error(); got == "" {
		t.Fatalf("FetchError.Error must be non-empty")
	}
}

func TestFetchError_ErrorIncludesMode(t *testing.T) {
	e := &FetchError{Mode: ModeNoise}
	if got := e.Error(); !contains(got, string(ModeNoise)) {
		t.Fatalf("FetchError.Error %q must include mode %q", got, ModeNoise)
	}
}

// =============================================================================
// toCABundle
// =============================================================================

func TestToCABundle_NilReturnsNil(t *testing.T) {
	if got := toCABundle(nil); got != nil {
		t.Fatalf("toCABundle(nil) = %+v, want nil", got)
	}
}

// contains is a tiny substring check used to avoid an extra import.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
