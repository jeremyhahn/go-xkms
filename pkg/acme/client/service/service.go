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

package service

import (
	"context"
	"log/slog"
)

// Service is the top-level ACME client service that composes account management,
// certificate lifecycle, and automatic renewal into a single entry point.
type Service struct {
	config       *Config
	accounts     AccountManager
	certificates CertificateManager
	devices      DeviceManager
	renewal      *RenewalOrchestrator
	deployer     *Deployer
	logger       *slog.Logger
}

// NewService creates a new multi-account ACME client Service from the given configuration.
func NewService(config *Config, logger *slog.Logger) (*Service, error) {
	deployer := NewDeployer(logger)
	accounts := NewAccountManager(config, logger)
	certificates := NewCertificateManager(config, accounts, deployer, logger)
	devices := NewDeviceManager(config, accounts, logger)
	renewal := NewRenewalOrchestrator(config, certificates, logger)

	return &Service{
		config:       config,
		accounts:     accounts,
		certificates: certificates,
		devices:      devices,
		renewal:      renewal,
		deployer:     deployer,
		logger:       logger,
	}, nil
}

// Accounts returns the account manager.
func (s *Service) Accounts() AccountManager {
	return s.accounts
}

// Certificates returns the certificate manager.
func (s *Service) Certificates() CertificateManager {
	return s.certificates
}

// Devices returns the device manager.
func (s *Service) Devices() DeviceManager {
	return s.devices
}

// Deployer returns the certificate deployer.
func (s *Service) Deployer() *Deployer {
	return s.deployer
}

// Config returns the current service configuration.
func (s *Service) Config() *Config {
	return s.config
}

// StartRenewal starts the automatic certificate renewal monitoring.
func (s *Service) StartRenewal(ctx context.Context) error {
	return s.renewal.Start(ctx)
}

// StopRenewal gracefully stops the renewal monitoring.
func (s *Service) StopRenewal() error {
	return s.renewal.Stop()
}
