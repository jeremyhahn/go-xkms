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

package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

// Deployer writes issued certificates and private keys to filesystem paths
// and executes post-deployment hooks.
type Deployer struct {
	logger *slog.Logger
}

// NewDeployer creates a new Deployer.
func NewDeployer(logger *slog.Logger) *Deployer {
	return &Deployer{
		logger: logger,
	}
}

// Deploy writes the certificate and private key PEM data to the paths specified
// in the DeployConfig, then executes the post-deployment hook if configured.
func (d *Deployer) Deploy(ctx context.Context, certPEM []byte, keyPEM []byte, cfg *DeployConfig) error {
	if cfg == nil {
		return ErrDeployFailed{
			CertName: "unknown",
			Err:      errors.New("deploy config is nil"),
		}
	}
	if len(certPEM) == 0 {
		return ErrDeployFailed{
			CertName: cfg.CertPath,
			Err:      errors.New("certificate PEM data is empty"),
		}
	}
	if cfg.CertPath == "" {
		return ErrDeployFailed{
			CertName: cfg.CertPath,
			Err:      errors.New("certificate path is empty"),
		}
	}
	if cfg.KeyPath == "" {
		return ErrDeployFailed{
			CertName: cfg.KeyPath,
			Err:      errors.New("key path is empty"),
		}
	}
	if len(keyPEM) == 0 {
		return ErrDeployFailed{
			CertName: cfg.KeyPath,
			Err:      errors.New("private key PEM data is empty"),
		}
	}

	// Create parent directories for certificate and key paths
	if err := os.MkdirAll(filepath.Dir(cfg.CertPath), 0755); err != nil {
		return ErrDeployFailed{CertName: cfg.CertPath, Err: err}
	}
	if err := os.MkdirAll(filepath.Dir(cfg.KeyPath), 0755); err != nil {
		return ErrDeployFailed{CertName: cfg.KeyPath, Err: err}
	}

	// Write certificate PEM (public data, world-readable)
	if err := os.WriteFile(cfg.CertPath, certPEM, 0644); err != nil {
		return ErrDeployFailed{CertName: cfg.CertPath, Err: err}
	}
	d.logger.Info("certificate deployed", slog.String("path", cfg.CertPath))

	// Write private key PEM (restricted permissions)
	if err := os.WriteFile(cfg.KeyPath, keyPEM, 0600); err != nil {
		return ErrDeployFailed{CertName: cfg.KeyPath, Err: err}
	}
	d.logger.Info("private key deployed", slog.String("path", cfg.KeyPath))

	// Execute post-deployment hook if configured
	if cfg.PostHook != "" {
		cmd := exec.CommandContext(ctx, "sh", "-c", cfg.PostHook) // #nosec G204 -- PostHook is user-configured, not tainted input
		output, err := cmd.CombinedOutput()
		if err != nil {
			return ErrPostHookFailed{Hook: cfg.PostHook, Err: err}
		}
		d.logger.Info("post-deployment hook executed",
			slog.String("hook", cfg.PostHook),
			slog.String("output", string(output)))
	}

	return nil
}
