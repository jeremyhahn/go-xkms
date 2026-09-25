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
	"crypto/x509"
	"log/slog"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client"
)

// Compile-time interface check.
var _ DeviceManager = (*deviceManager)(nil)

// DeviceManager manages the lifecycle of TPM device identities defined in
// the configuration. Enrollment issues a device's IAK and IDevID
// certificates via the enroll-01 challenge; attestation proves the device's
// current platform state against a set of PCRs via the device-attest-01
// challenge.
type DeviceManager interface {
	// Enroll performs TPM device enrollment for the named spec via the
	// enroll-01 challenge, returning the issued IAK and IDevID
	// certificates.
	Enroll(ctx context.Context, name string) (*DeviceEnrollResult, error)

	// Attest performs TPM device attestation for the named spec via the
	// device-attest-01 challenge, returning the issued attestation
	// certificate.
	Attest(ctx context.Context, name string) (*DeviceAttestResult, error)

	// List returns device specs, optionally filtered by account name.
	List(accountFilter string) map[string]*DeviceSpec

	// Show returns metadata about a managed device.
	Show(name string) (*ManagedDeviceInfo, error)
}

// DeviceEnrollResult holds the outcome of a device enrollment.
type DeviceEnrollResult struct {
	IAKCertificate    *x509.Certificate
	IDevIDCertificate *x509.Certificate
	Chain             []*x509.Certificate
}

// DeviceAttestResult holds the outcome of a device attestation.
type DeviceAttestResult struct {
	Certificate *x509.Certificate
}

// ManagedDeviceInfo holds metadata about an enrolled or attested device.
type ManagedDeviceInfo struct {
	Name        string
	Spec        *DeviceSpec
	Enrollment  *DeviceEnrollResult
	Attestation *DeviceAttestResult
	EnrolledAt  *time.Time
	AttestedAt  *time.Time
}

// deviceManager is the concrete implementation of DeviceManager.
type deviceManager struct {
	config   *Config
	accounts AccountManager
	logger   *slog.Logger
	managed  sync.Map // map[string]*ManagedDeviceInfo
}

// NewDeviceManager creates a new DeviceManager backed by the given
// configuration, account manager, and logger.
func NewDeviceManager(config *Config, accounts AccountManager, logger *slog.Logger) DeviceManager {
	return &deviceManager{
		config:   config,
		accounts: accounts,
		logger:   logger,
	}
}

// Enroll performs TPM device enrollment for the named spec via the
// enroll-01 challenge, returning the issued IAK and IDevID certificates.
func (dm *deviceManager) Enroll(ctx context.Context, name string) (*DeviceEnrollResult, error) {
	spec, ok := dm.config.Devices[name]
	if !ok {
		return nil, ErrDeviceSpecNotFound{Name: name}
	}

	acmeClient, err := dm.accounts.Client(ctx, spec.Account)
	if err != nil {
		return nil, err
	}

	tpmModule, err := openDeviceTPM(name, spec, dm.logger)
	if err != nil {
		return nil, err
	}
	defer dm.closeTPM(name, tpmModule)

	enrollCfg := buildEnrollmentConfig(spec, tpmModule, client.ChallengeTypeEnroll01)

	result, err := acmeClient.EnrollDevice(ctx, enrollCfg)
	if err != nil {
		return nil, err
	}

	enrollResult := &DeviceEnrollResult{
		IAKCertificate:    result.IAKCertificate,
		IDevIDCertificate: result.IDevIDCertificate,
		Chain:             result.Chain,
	}

	now := time.Now()
	info := dm.loadOrCreateInfo(name, spec)
	info.Enrollment = enrollResult
	info.EnrolledAt = &now
	dm.managed.Store(name, info)

	dm.logger.InfoContext(ctx, "device enrolled",
		slog.String("name", name),
		slog.String("idevid_subject", result.IDevIDCertificate.Subject.CommonName),
		slog.Time("idevid_expires", result.IDevIDCertificate.NotAfter),
	)

	return enrollResult, nil
}

// Attest performs TPM device attestation for the named spec via the
// device-attest-01 challenge, returning the issued attestation certificate.
func (dm *deviceManager) Attest(ctx context.Context, name string) (*DeviceAttestResult, error) {
	spec, ok := dm.config.Devices[name]
	if !ok {
		return nil, ErrDeviceSpecNotFound{Name: name}
	}

	acmeClient, err := dm.accounts.Client(ctx, spec.Account)
	if err != nil {
		return nil, err
	}

	tpmModule, err := openDeviceTPM(name, spec, dm.logger)
	if err != nil {
		return nil, err
	}
	defer dm.closeTPM(name, tpmModule)

	attestCfg := buildEnrollmentConfig(spec, tpmModule, client.ChallengeTypeDeviceAttest01)

	cert, err := acmeClient.DeviceAttest(ctx, attestCfg, spec.PCRSelection)
	if err != nil {
		return nil, err
	}

	attestResult := &DeviceAttestResult{Certificate: cert}

	now := time.Now()
	info := dm.loadOrCreateInfo(name, spec)
	info.Attestation = attestResult
	info.AttestedAt = &now
	dm.managed.Store(name, info)

	dm.logger.InfoContext(ctx, "device attested",
		slog.String("name", name),
		slog.String("subject", cert.Subject.CommonName),
		slog.Time("expires", cert.NotAfter),
	)

	return attestResult, nil
}

// List returns device specs, optionally filtered by account name.
// If accountFilter is empty, all specs are returned.
func (dm *deviceManager) List(accountFilter string) map[string]*DeviceSpec {
	if accountFilter == "" {
		return dm.config.Devices
	}

	filtered := make(map[string]*DeviceSpec)
	for name, spec := range dm.config.Devices {
		if spec.Account == accountFilter {
			filtered[name] = spec
		}
	}
	return filtered
}

// Show returns metadata about a managed device.
func (dm *deviceManager) Show(name string) (*ManagedDeviceInfo, error) {
	val, ok := dm.managed.Load(name)
	if !ok {
		if _, specExists := dm.config.Devices[name]; specExists {
			return nil, ErrDeviceNotEnrolled{Name: name}
		}
		return nil, ErrDeviceSpecNotFound{Name: name}
	}
	return val.(*ManagedDeviceInfo), nil
}

// loadOrCreateInfo returns the existing ManagedDeviceInfo for name, or a new
// one seeded with spec when none has been recorded yet.
func (dm *deviceManager) loadOrCreateInfo(name string, spec *DeviceSpec) *ManagedDeviceInfo {
	if val, ok := dm.managed.Load(name); ok {
		return val.(*ManagedDeviceInfo)
	}
	return &ManagedDeviceInfo{Name: name, Spec: spec}
}

// closeTPM releases tpmModule, logging rather than propagating a close
// failure: the enrollment or attestation result it guards has already been
// determined by the time Close runs.
func (dm *deviceManager) closeTPM(name string, tpmModule client.TPMModule) {
	if err := tpmModule.Close(); err != nil {
		dm.logger.Warn("failed to close TPM module",
			slog.String("device", name),
			slog.String("error", err.Error()),
		)
	}
}

// buildEnrollmentConfig assembles the client.EnrollmentConfig EnrollDevice
// and DeviceAttest consume from a DeviceSpec, the already-opened TPM module,
// and the challenge type being driven. It does not duplicate
// client.EnrollmentConfig.Validate's checks — EnrollDevice and DeviceAttest
// both call it before doing anything else.
func buildEnrollmentConfig(spec *DeviceSpec, tpmModule client.TPMModule, challenge client.ChallengeType) *client.EnrollmentConfig {
	return &client.EnrollmentConfig{
		Challenge:    string(challenge),
		IPAddress:    spec.Identifier,
		TPMModule:    tpmModule,
		Port:         spec.Challenge.Port,
		ListenHost:   spec.Challenge.ListenHost,
		CommonName:   spec.CommonName,
		PCRSelection: spec.PCRSelection,
		Timeout:      spec.Challenge.Timeout,
	}
}
