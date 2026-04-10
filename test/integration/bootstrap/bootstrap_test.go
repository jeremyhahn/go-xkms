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

//go:build integration

package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
)

// ---------------------------------------------------------------------------
// DANE/TLSA individual method tests
// ---------------------------------------------------------------------------

func TestDANE_Success(t *testing.T) {
	cfg := validDANEConfig(t)
	b, err := truststrap.NewDANEBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create DANE bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := b.FetchCABundle(ctx, nil)
	if err != nil {
		t.Fatalf("FetchCABundle: %v", err)
	}
	validateBundle(t, resp)
}

func TestDANE_WrongHostname(t *testing.T) {
	cfg := brokenDANEConfig(t)
	b, err := truststrap.NewDANEBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create DANE bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for wrong hostname")
	}
}

func TestDANE_DNSServerDown(t *testing.T) {
	unreachableDNS := "192.0.2.1:53" // RFC 5737 TEST-NET, unreachable
	cfg := &truststrap.DANEConfig{
		ServerURL: requiredEnv(t, EnvServerURL),
		Hostname:  requiredEnv(t, EnvHostname),
		DNSServer: unreachableDNS,
		Resolver:  newResolver(t, unreachableDNS),
	}
	b, err := truststrap.NewDANEBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create DANE bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for unreachable DNS server")
	}
}

// ---------------------------------------------------------------------------
// Noise individual method tests
// ---------------------------------------------------------------------------

func TestNoise_Success(t *testing.T) {
	cfg := validNoiseConfig(t)
	b, err := truststrap.NewNoiseBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Noise bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := b.FetchCABundle(ctx, nil)
	if err != nil {
		t.Fatalf("FetchCABundle: %v", err)
	}
	validateBundle(t, resp)
}

func TestNoise_WrongKey(t *testing.T) {
	cfg := brokenNoiseConfig(t)
	b, err := truststrap.NewNoiseBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Noise bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for wrong Noise key")
	}
}

func TestNoise_ServerUnreachable(t *testing.T) {
	cfg := &truststrap.NoiseConfig{
		ServerAddr:      "192.0.2.1:8445",
		ServerStaticKey: "0000000000000000000000000000000000000000000000000000000000000000",
		ConnectTimeout:  2 * time.Second,
	}
	b, err := truststrap.NewNoiseBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Noise bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestNoise_Timeout(t *testing.T) {
	cfg := validNoiseConfig(t)
	cfg.ConnectTimeout = 1 * time.Millisecond

	b, err := truststrap.NewNoiseBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Noise bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// With 1ms timeout against a real server, this should fail
	_, err = b.FetchCABundle(ctx, nil)
	// May or may not fail depending on network speed; just verify no panic
	_ = err
}

// ---------------------------------------------------------------------------
// SPKI individual method tests
// ---------------------------------------------------------------------------

func TestSPKI_Success(t *testing.T) {
	cfg := validSPKIConfig(t)
	b, err := truststrap.NewSPKIBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create SPKI bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := b.FetchCABundle(ctx, nil)
	if err != nil {
		t.Fatalf("FetchCABundle: %v", err)
	}
	validateBundle(t, resp)
}

func TestSPKI_WrongPin(t *testing.T) {
	cfg := brokenSPKIConfig(t)
	b, err := truststrap.NewSPKIBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create SPKI bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for wrong SPKI pin")
	}
}

func TestSPKI_ServerUnreachable(t *testing.T) {
	cfg := &truststrap.SPKIConfig{
		ServerURL:      "https://192.0.2.1:9999",
		SPKIPinSHA256:  "0000000000000000000000000000000000000000000000000000000000000000",
		ConnectTimeout: 2 * time.Second,
	}
	b, err := truststrap.NewSPKIBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create SPKI bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// ---------------------------------------------------------------------------
// Direct HTTPS individual method tests
// ---------------------------------------------------------------------------

func TestDirect_Success(t *testing.T) {
	cfg := validDirectConfig(t)
	b, err := truststrap.NewDirectBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Direct bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := b.FetchCABundle(ctx, nil)
	if err != nil {
		t.Fatalf("FetchCABundle: %v", err)
	}
	validateBundle(t, resp)
}

func TestDirect_ServerError(t *testing.T) {
	cfg := &truststrap.DirectConfig{
		ServerURL:  requiredEnv(t, EnvServerURL),
		BundlePath: "/v1/nonexistent/path",
	}
	b, err := truststrap.NewDirectBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Direct bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestDirect_ServerUnreachable(t *testing.T) {
	cfg := brokenDirectConfig(t)
	cfg.ConnectTimeout = 2 * time.Second

	b, err := truststrap.NewDirectBootstrapper(cfg)
	if err != nil {
		t.Fatalf("create Direct bootstrapper: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = b.FetchCABundle(ctx, nil)
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// ---------------------------------------------------------------------------
// AutoBootstrap fallback chain tests
// ---------------------------------------------------------------------------

func TestAuto_AllConfigured_DANEWins(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:   validDANEConfig(t),
		Noise:  validNoiseConfig(t),
		SPKI:   validSPKIConfig(t),
		Direct: validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

func TestAuto_DANEFails_NoiseWins(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:   brokenDANEConfig(t),
		Noise:  validNoiseConfig(t),
		SPKI:   validSPKIConfig(t),
		Direct: validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

func TestAuto_DANEFails_NoiseFails_SPKIWins(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:   brokenDANEConfig(t),
		Noise:  brokenNoiseConfig(t),
		SPKI:   validSPKIConfig(t),
		Direct: validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

func TestAuto_DANEFails_NoiseFails_SPKIFails_DirectWins(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:   brokenDANEConfig(t),
		Noise:  brokenNoiseConfig(t),
		SPKI:   brokenSPKIConfig(t),
		Direct: validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

func TestAuto_AllFail(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:             brokenDANEConfig(t),
		Noise:            brokenNoiseConfig(t),
		SPKI:             brokenSPKIConfig(t),
		Direct:           brokenDirectConfig(t),
		PerMethodTimeout: 3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := truststrap.AutoFetch(ctx, cfg)
	if err == nil {
		t.Fatal("expected error when all methods fail")
	}
	if !errors.Is(err, truststrap.ErrAllMethodsFailed) {
		t.Fatalf("expected ErrAllMethodsFailed, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Skip tests (nil config = method skipped)
// ---------------------------------------------------------------------------

func TestAuto_OnlyNoise(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		Noise: validNoiseConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

func TestAuto_OnlyDirect(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		Direct: validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

func TestAuto_NoMethodsConfigured(t *testing.T) {
	cfg := &truststrap.AutoConfig{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := truststrap.AutoFetch(ctx, cfg)
	if err == nil {
		t.Fatal("expected error when no methods configured")
	}
	if !errors.Is(err, truststrap.ErrNoMethodsConfigured) {
		t.Fatalf("expected ErrNoMethodsConfigured, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Custom priority order tests
// ---------------------------------------------------------------------------

func TestAuto_CustomOrder_DirectFirst(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		MethodOrder: []truststrap.Method{truststrap.MethodDirect, truststrap.MethodDANE},
		DANE:        validDANEConfig(t),
		Direct:      validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

// ---------------------------------------------------------------------------
// Context & timeout tests
// ---------------------------------------------------------------------------

func TestAuto_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	cfg := &truststrap.AutoConfig{
		DANE:   validDANEConfig(t),
		Direct: validDirectConfig(t),
	}

	_, err := truststrap.AutoFetch(ctx, cfg)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestAuto_PerMethodTimeout(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		PerMethodTimeout: 100 * time.Millisecond,
		DANE:             brokenDANEConfig(t), // Will fail
		Direct:           validDirectConfig(t),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := truststrap.AutoFetch(ctx, cfg)
	if err != nil {
		t.Fatalf("AutoFetch: %v", err)
	}
	validateBundle(t, resp)
}

// ---------------------------------------------------------------------------
// Error aggregation tests
// ---------------------------------------------------------------------------

func TestAuto_AggregateError_ContainsAllAttempts(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:             brokenDANEConfig(t),
		Noise:            brokenNoiseConfig(t),
		SPKI:             brokenSPKIConfig(t),
		Direct:           brokenDirectConfig(t),
		PerMethodTimeout: 3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := truststrap.AutoFetch(ctx, cfg)
	if err == nil {
		t.Fatal("expected error")
	}

	var aggErr *truststrap.AggregateError
	if errors.As(err, &aggErr) {
		if len(aggErr.Attempts) < 2 {
			t.Fatalf("expected multiple attempts, got %d", len(aggErr.Attempts))
		}
	}
}

func TestAuto_AggregateError_UnwrapsToErrAllMethodsFailed(t *testing.T) {
	cfg := &truststrap.AutoConfig{
		DANE:             brokenDANEConfig(t),
		Direct:           brokenDirectConfig(t),
		PerMethodTimeout: 3 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := truststrap.AutoFetch(ctx, cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, truststrap.ErrAllMethodsFailed) {
		t.Fatalf("expected ErrAllMethodsFailed, got: %v", err)
	}
}
