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

package server

import (
	"crypto/ecdh"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	phonebackend "github.com/jeremyhahn/go-xkms/pkg/backend/phone"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/devicereg"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	// Register the Android platform verifier for phone attestation.
	_ "github.com/jeremyhahn/go-xkms/pkg/backend/phone/android"
)

// initPhoneBackend validates the phone backend configuration and logs that it
// is configured. The actual backend creation is deferred until a phone connects
// and provides a Sender, because the phone backend requires an active BLE or
// TCP connection which is established by the xkey binary acting as a bridge.
func (s *Server) initPhoneBackend() error {
	if s.config.Backends.Phone == nil || !s.config.Backends.Phone.Enabled {
		return nil
	}

	s.logger.Info("phone backend configured",
		"transport", s.config.Backends.Phone.Transport,
		"device_address", s.config.Backends.Phone.DeviceAddress,
	)

	// Phone backend registration is deferred until a phone connects.
	// The xkey binary or phone BLE handler will provide a Sender
	// and call RegisterPhoneBackend() when the connection is established.
	return nil
}

// RegisterPhoneBackend creates and registers the phone backend using
// the provided Sender. This is called when a phone connects and provides
// an active JSON-RPC transport (typically from the xkey binary acting
// as a bridge between BLE/TCP and xkmsd).
//
// The Sender is responsible for encrypting, sending, and receiving JSON-RPC
// messages to/from the phone. The backend does not manage the transport
// lifecycle -- the caller owns the Sender.
//
// If a phone backend is already registered, it is closed and replaced.
func (s *Server) RegisterPhoneBackend(sender phonebackend.Sender) error {
	if sender == nil {
		return ErrNilSender
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close existing phone backend if present.
	if existing, ok := s.keyProviders["phone"]; ok {
		if err := existing.Close(); err != nil {
			s.logger.Warn("failed to close existing phone backend",
				slog.Any("error", err))
		}
		delete(s.keyProviders, "phone")
	}

	// Build phone backend config from server config.
	phoneCfg := s.config.Backends.Phone
	if phoneCfg == nil {
		return ErrPhoneConfigNil
	}

	// NoiseStaticKey already carries its resolved plaintext here on a normal
	// boot: Server.resolveConfigSecrets walks the whole loaded configuration,
	// s.config (and so phoneCfg, part of that same tree) included, once the
	// credential service comes up in Server.New -- well before any phone
	// connects. A credential:// reference that resolver could not claim (no
	// credential service was ever wired, e.g. an embedder constructing
	// *Server directly without going through New) falls through to
	// SecretValueBytes below, which fails closed with
	// *types.SecretReferenceUnresolvedError rather than using the unclaimed
	// reference text as the Noise key.
	//
	// phonebackend.Config.NoiseStaticKey is validated, never read, by the
	// backend, so the plaintext is handed over as bytes and wiped below as
	// soon as NewBackend returns.
	noiseStaticKey, err := types.SecretValueBytes(s.ctx, phoneCfg.NoiseStaticKey)
	if err != nil {
		return errors.Join(ErrPhoneBackendCreate, err)
	}
	defer secure.Wipe(noiseStaticKey)

	backendConfig := &phonebackend.Config{
		Transport:      phoneCfg.Transport,
		DeviceAddress:  phoneCfg.DeviceAddress,
		NoiseStaticKey: types.SecretBytes(noiseStaticKey),
		PhoneStaticKey: phoneCfg.PhoneStaticKey,
		RequestTimeout: phoneCfg.RequestTimeout,
		Logger:         s.logger,
	}

	// Apply default timeout if not configured.
	if backendConfig.RequestTimeout == 0 {
		backendConfig.RequestTimeout = phonebackend.DefaultRequestTimeout
	}

	backend, err := phonebackend.NewBackend(backendConfig, sender)
	if err != nil {
		return errors.Join(ErrPhoneBackendCreate, err)
	}

	// Backend mode: go-xkms is the verifier. The phone is accepted only
	// while its device-registry record is active and bound to its key.
	if err := s.verifyPhoneDevice(phoneCfg); err != nil {
		if closeErr := backend.Close(); closeErr != nil {
			s.logger.Warn("failed to close refused phone backend",
				slog.Any("error", closeErr))
		}
		return err
	}

	s.keyProviders["phone"] = backend
	s.logger.Info("phone backend registered",
		"transport", phoneCfg.Transport,
		"device_address", phoneCfg.DeviceAddress,
	)
	return nil
}

// verifyPhoneDevice refuses, with ErrPhoneDeviceRefused, a phone whose
// device-registry record (phoneCfg.Tenant, phoneCfg.DeviceID) is missing,
// revoked, or carries an identity key other than phoneCfg.PhoneStaticKey.
// The identity key is SPKI DER of the phone's X25519 Noise static key.
// Callers hold s.mu.
func (s *Server) verifyPhoneDevice(phoneCfg *config.PhoneConfig) error {
	reg, err := s.phoneDeviceRegistry()
	if err != nil {
		return errors.Join(ErrPhoneDeviceRefused, err)
	}
	device, err := reg.Get(s.ctx, phoneCfg.Tenant, phoneCfg.DeviceID)
	if err != nil {
		return errors.Join(ErrPhoneDeviceRefused, err)
	}
	if !device.Active() {
		return fmt.Errorf("%w: device %q is revoked", ErrPhoneDeviceRefused, device.ID)
	}
	want, err := hex.DecodeString(phoneCfg.PhoneStaticKey)
	if err != nil {
		return fmt.Errorf("%w: phone_static_key is not hex: %v", ErrPhoneDeviceRefused, err)
	}
	pub, err := x509.ParsePKIXPublicKey(device.IdentityKey)
	if err != nil {
		return fmt.Errorf("%w: device %q identity key: %v", ErrPhoneDeviceRefused, device.ID, err)
	}
	key, ok := pub.(*ecdh.PublicKey)
	if !ok || key.Curve() != ecdh.X25519() || subtle.ConstantTimeCompare(key.Bytes(), want) != 1 {
		return fmt.Errorf("%w: device %q identity key is not the phone's key", ErrPhoneDeviceRefused, device.ID)
	}
	return nil
}

// phoneDeviceRegistry returns the device registry, opening it on the
// datastore at first use. Callers hold s.mu.
func (s *Server) phoneDeviceRegistry() (*devicereg.Registry, error) {
	if s.deviceRegistry != nil {
		return s.deviceRegistry, nil
	}
	daos, err := s.daoFactory(devicereg.DatabaseName)
	if err != nil {
		return nil, err
	}
	reg, err := devicereg.NewRegistry(daos)
	if err != nil {
		return nil, err
	}
	s.deviceRegistry = reg
	return reg, nil
}

// UnregisterPhoneBackend removes the phone backend, typically called when
// the phone disconnects.
func (s *Server) UnregisterPhoneBackend() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.keyProviders["phone"]
	if !ok {
		return nil
	}

	if err := existing.Close(); err != nil {
		s.logger.Warn("failed to close phone backend",
			slog.Any("error", err))
	}

	delete(s.keyProviders, "phone")
	s.logger.Info("phone backend unregistered")
	return nil
}
