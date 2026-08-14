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

package client

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	caerrors "github.com/jeremyhahn/go-xkms/pkg/acme/errors"
)

var (
	ErrRenewalServiceNotRunning     = errors.New("acme-renewal: service not running")
	ErrRenewalServiceAlreadyRunning = errors.New("acme-renewal: service already running")
	ErrNilClient                    = errors.New("acme-renewal: nil ACME client provided")
	ErrNilRenewalConfig             = errors.New("acme-renewal: nil renewal config provided")
	ErrCertificateAlreadyRegistered = errors.New("acme-renewal: certificate already registered")
)

// RenewalService manages automatic certificate renewal
type RenewalService struct {
	client       *Client
	config       *RenewalConfig
	logger       *slog.Logger
	certificates sync.Map // map[string]*CertificateInfo
	running      atomic.Bool
	stopChan     chan struct{}
	wg           sync.WaitGroup
	mutex        sync.RWMutex
}

// NewRenewalService creates a new certificate renewal service
func NewRenewalService(client *Client, config *RenewalConfig, logger *slog.Logger) (*RenewalService, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if config == nil {
		config = DefaultRenewalConfig()
	}
	if logger == nil {
		logger = slog.Default()
	}

	if err := config.Validate(); err != nil {
		return nil, caerrors.MalformedError("invalid renewal config: %v", err)
	}

	return &RenewalService{
		client:   client,
		config:   config,
		logger:   logger,
		stopChan: make(chan struct{}),
	}, nil
}

// RegisterCertificate registers a certificate for automatic renewal
func (rs *RenewalService) RegisterCertificate(cert *x509.Certificate, req *CertificateRequest, identifier string) error {
	if cert == nil {
		return caerrors.MalformedError("nil certificate provided")
	}
	if req == nil {
		return caerrors.MalformedError("nil certificate request provided")
	}
	if identifier == "" {
		identifier = cert.Subject.CommonName
	}

	// Check if already registered
	if _, exists := rs.certificates.Load(identifier); exists {
		return ErrCertificateAlreadyRegistered
	}

	certInfo := &CertificateInfo{
		Certificate: cert,
		Request:     req,
		Identifier:  identifier,
	}

	rs.certificates.Store(identifier, certInfo)
	rs.logger.Info("registered certificate for renewal",
		slog.String("identifier", identifier),
		slog.String("subject", cert.Subject.CommonName),
		slog.Time("not_after", cert.NotAfter))

	return nil
}

// UnregisterCertificate removes a certificate from automatic renewal
func (rs *RenewalService) UnregisterCertificate(identifier string) {
	rs.certificates.Delete(identifier)
	rs.logger.Info("unregistered certificate from renewal", slog.String("identifier", identifier))
}

// Start starts the renewal service daemon
func (rs *RenewalService) Start(ctx context.Context) error {
	if rs.running.Load() {
		return ErrRenewalServiceAlreadyRunning
	}

	if !rs.config.Enabled {
		rs.logger.Info("renewal service disabled")
		return nil
	}

	rs.running.Store(true)
	rs.stopChan = make(chan struct{})

	rs.logger.Info("starting certificate renewal service",
		slog.Duration("check_interval", rs.config.CheckInterval),
		slog.Float64("renewal_threshold", rs.config.RenewalThreshold))

	rs.wg.Add(1)
	go rs.run(ctx)

	return nil
}

// Stop stops the renewal service daemon
func (rs *RenewalService) Stop() error {
	if !rs.running.Load() {
		return ErrRenewalServiceNotRunning
	}

	rs.logger.Info("stopping certificate renewal service")
	close(rs.stopChan)
	rs.wg.Wait()
	rs.running.Store(false)

	rs.logger.Info("certificate renewal service stopped")
	return nil
}

// run is the main renewal service loop
func (rs *RenewalService) run(ctx context.Context) {
	defer rs.wg.Done()

	ticker := time.NewTicker(rs.config.CheckInterval)
	defer ticker.Stop()

	// Perform initial check immediately
	rs.checkAndRenewCertificates(ctx)

	for {
		select {
		case <-ctx.Done():
			rs.logger.Info("renewal service context cancelled")
			return
		case <-rs.stopChan:
			rs.logger.Info("renewal service stop signal received")
			return
		case <-ticker.C:
			rs.checkAndRenewCertificates(ctx)
		}
	}
}

// checkAndRenewCertificates checks all registered certificates and renews if needed
func (rs *RenewalService) checkAndRenewCertificates(ctx context.Context) {
	rs.logger.Debug("checking certificates for renewal")

	var checked, renewed, failed int

	rs.certificates.Range(func(key, value interface{}) bool {
		identifier := key.(string)
		certInfo := value.(*CertificateInfo)

		checked++
		status := rs.checkCertificate(certInfo)

		if status.ShouldRenew {
			rs.logger.Info("certificate needs renewal",
				slog.String("identifier", identifier),
				slog.String("subject", status.CertificateSubject),
				slog.Int("days_remaining", status.DaysRemaining))

			if err := rs.renewCertificate(ctx, certInfo); err != nil {
				failed++
				if rs.config.NotifyOnFailure {
					rs.logger.Error("certificate renewal failed",
						slog.String("identifier", identifier),
						slog.String("error", err.Error()))
				}
			} else {
				renewed++
				if rs.config.NotifyOnSuccess {
					rs.logger.Info("certificate renewed successfully",
						slog.String("identifier", identifier),
						slog.String("subject", status.CertificateSubject))
				}
			}
		}

		return true // keep walking the remaining certificates
	})

	rs.logger.Debug("certificate check complete",
		slog.Int("checked", checked),
		slog.Int("renewed", renewed),
		slog.Int("failed", failed))
}

// checkCertificate checks if a certificate needs renewal
func (rs *RenewalService) checkCertificate(certInfo *CertificateInfo) *RenewalStatus {
	cert := certInfo.Certificate
	now := time.Now()

	// Calculate remaining validity period
	totalDuration := cert.NotAfter.Sub(cert.NotBefore)
	elapsed := now.Sub(cert.NotBefore)
	remaining := cert.NotAfter.Sub(now)

	// Calculate days remaining
	daysRemaining := int(remaining.Hours() / 24)

	// Determine if renewal is needed based on threshold
	renewalPoint := time.Duration(float64(totalDuration) * rs.config.RenewalThreshold)
	shouldRenew := remaining <= renewalPoint

	status := &RenewalStatus{
		CertificateSubject: cert.Subject.CommonName,
		NotBefore:          cert.NotBefore.Format(time.RFC3339),
		NotAfter:           cert.NotAfter.Format(time.RFC3339),
		DaysRemaining:      daysRemaining,
		ShouldRenew:        shouldRenew,
	}

	rs.logger.Debug("checked certificate",
		slog.String("subject", cert.Subject.CommonName),
		slog.Int("days_remaining", daysRemaining),
		slog.Float64("elapsed_pct", elapsed.Seconds()/totalDuration.Seconds()),
		slog.Bool("should_renew", shouldRenew))

	return status
}

// renewCertificate attempts to renew a certificate with retry logic
func (rs *RenewalService) renewCertificate(ctx context.Context, certInfo *CertificateInfo) error {
	var lastErr error

	for attempt := 0; attempt <= rs.config.MaxRetries; attempt++ {
		if attempt > 0 {
			rs.logger.Info("retrying certificate renewal",
				slog.Int("attempt", attempt),
				slog.Int("max_retries", rs.config.MaxRetries),
				slog.String("identifier", certInfo.Identifier))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(rs.config.RetryInterval):
			}
		}

		newCert, err := rs.client.RenewCertificate(ctx, certInfo.Certificate, certInfo.Request)
		if err != nil {
			lastErr = caerrors.InternalServerError("renewal attempt %d failed: %v", attempt+1, err)
			rs.logger.Warn("renewal attempt failed",
				slog.Int("attempt", attempt+1),
				slog.String("error", err.Error()))
			continue
		}

		// Update the certificate info with the new certificate
		rs.mutex.Lock()
		certInfo.Certificate = newCert
		rs.certificates.Store(certInfo.Identifier, certInfo)
		rs.mutex.Unlock()

		rs.logger.Info("certificate renewed successfully",
			slog.String("identifier", certInfo.Identifier),
			slog.String("subject", newCert.Subject.CommonName),
			slog.Time("not_before", newCert.NotBefore),
			slog.Time("not_after", newCert.NotAfter))

		return nil
	}

	return caerrors.InternalServerError("failed to renew certificate after %d attempts: %v", rs.config.MaxRetries+1, lastErr)
}

// GetRenewalStatus returns the renewal status for all registered certificates
func (rs *RenewalService) GetRenewalStatus() []*RenewalStatus {
	statuses := make([]*RenewalStatus, 0)

	rs.certificates.Range(func(key, value interface{}) bool {
		certInfo := value.(*CertificateInfo)
		status := rs.checkCertificate(certInfo)
		statuses = append(statuses, status)
		return true
	})

	return statuses
}

// IsRunning returns whether the renewal service is currently running
func (rs *RenewalService) IsRunning() bool {
	return rs.running.Load()
}

// GetCertificateCount returns the number of registered certificates
func (rs *RenewalService) GetCertificateCount() int {
	count := 0
	rs.certificates.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// ForceRenewal forces immediate renewal of a specific certificate
func (rs *RenewalService) ForceRenewal(ctx context.Context, identifier string) error {
	value, exists := rs.certificates.Load(identifier)
	if !exists {
		return caerrors.NotFoundError("certificate not found: %s", identifier)
	}

	certInfo := value.(*CertificateInfo)
	rs.logger.Info("forcing certificate renewal", slog.String("identifier", identifier))

	return rs.renewCertificate(ctx, certInfo)
}

// RenewAll forces immediate renewal of all registered certificates
func (rs *RenewalService) RenewAll(ctx context.Context) error {
	rs.logger.Info("forcing renewal of all certificates")

	var errs []error
	rs.certificates.Range(func(key, value interface{}) bool {
		identifier := key.(string)
		certInfo := value.(*CertificateInfo)

		if err := rs.renewCertificate(ctx, certInfo); err != nil {
			errs = append(errs, caerrors.InternalServerError("%s: %v", identifier, err))
		}

		return true
	})

	if len(errs) > 0 {
		return caerrors.InternalServerError("failed to renew %d certificates: %v", len(errs), errs)
	}

	return nil
}
