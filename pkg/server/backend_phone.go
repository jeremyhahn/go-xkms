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
	"errors"
	"log/slog"

	phonebackend "github.com/jeremyhahn/go-xkms/pkg/backend/phone"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"

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
	// phonebackend.Config.NoiseStaticKey takes a plain hex string; the
	// plaintext leaves phoneCfg.NoiseStaticKey's enclave only for this
	// assignment, the accepted boundary for a downstream API that is not
	// itself enclave-aware.
	noiseStaticKey, err := types.SecretValueBytes(phoneCfg.NoiseStaticKey)
	if err != nil {
		return errors.Join(ErrPhoneBackendCreate, err)
	}
	defer secure.Wipe(noiseStaticKey)

	backendConfig := &phonebackend.Config{
		Transport:      phoneCfg.Transport,
		DeviceAddress:  phoneCfg.DeviceAddress,
		NoiseStaticKey: string(noiseStaticKey),
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

	s.keyProviders["phone"] = backend
	s.logger.Info("phone backend registered",
		"transport", phoneCfg.Transport,
		"device_address", phoneCfg.DeviceAddress,
	)
	return nil
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
