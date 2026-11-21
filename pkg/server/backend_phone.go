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
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"

	phonebackend "github.com/jeremyhahn/go-xkms/pkg/backend/phone"
	"github.com/jeremyhahn/go-xkms/pkg/devicereg"
	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
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

// AuthenticatedPhoneSender is a phone Sender bound to one authenticated Noise
// session. RemoteStaticKey returns the peer's static public key (X25519, 32
// bytes) that the session handshake authenticated; the device registry binds
// the phone to that key, not to the configuration.
type AuthenticatedPhoneSender interface {
	phonebackend.Sender
	RemoteStaticKey() []byte
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
// If a phone backend is already registered, it is closed and replaced only
// after the new one passes every check; a refused call leaves it in place.
//
// Backend mode: the phone is accepted only when the device-registry record
// named by backends.phone.tenant/device_id is active and its identity key is
// the static key the sender's Noise session authenticated
// (AuthenticatedPhoneSender.RemoteStaticKey); otherwise the call fails with
// ErrPhoneDeviceRefused.
func (s *Server) RegisterPhoneBackend(sender AuthenticatedPhoneSender) error {
	if sender == nil {
		return ErrNilSender
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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

	// Backend mode: go-xkms is the verifier. The phone is accepted only while
	// its device-registry record is active and bound to the session's peer
	// key, and every request the backend sends re-reads that record, so a
	// revocation (from any process sharing the datastore) refuses the next
	// operation.
	reg, err := s.phoneDeviceRegistry()
	if err != nil {
		return errors.Join(ErrPhoneDeviceRefused, err)
	}
	guarded := &registryGuardedSender{
		inner:   sender,
		reg:     reg,
		tenant:  phoneCfg.Tenant,
		id:      phoneCfg.DeviceID,
		peerKey: bytes.Clone(sender.RemoteStaticKey()),
	}

	backend, err := phonebackend.NewBackend(backendConfig, guarded)
	if err != nil {
		return errors.Join(ErrPhoneBackendCreate, err)
	}

	if err := guarded.check(s.ctx); err != nil {
		if closeErr := backend.Close(); closeErr != nil {
			s.logger.Warn("failed to close refused phone backend",
				slog.Any("error", closeErr))
		}
		return err
	}

	// Only now, with the replacement accepted, is the existing backend
	// closed: a refused peer cannot disable the accepted phone.
	if existing, ok := s.keyProviders["phone"]; ok {
		if err := existing.Close(); err != nil {
			s.logger.Warn("failed to close existing phone backend",
				slog.Any("error", err))
		}
	}
	s.keyProviders["phone"] = backend
	s.logger.Info("phone backend registered",
		"transport", phoneCfg.Transport,
		"device_address", phoneCfg.DeviceAddress,
	)
	return nil
}

// registryGuardedSender is the Sender the phone backend sends through: it
// re-checks the device-registry record before every request, so a revoked
// or re-keyed device is refused with ErrPhoneDeviceRefused and no request
// reaches the phone.
type registryGuardedSender struct {
	inner      AuthenticatedPhoneSender
	reg        *devicereg.Registry
	tenant, id string
	peerKey    []byte
}

// check refuses unless the record is active and bound to peerKey.
func (g *registryGuardedSender) check(ctx context.Context) error {
	return checkPhoneDevice(ctx, g.reg, g.tenant, g.id, g.peerKey)
}

// SendRequest implements phonebackend.Sender.
func (g *registryGuardedSender) SendRequest(ctx context.Context, req *pairingproto.Request) (*pairingproto.Response, error) {
	if err := g.check(ctx); err != nil {
		return nil, err
	}
	return g.inner.SendRequest(ctx, req)
}

// checkPhoneDevice refuses, with ErrPhoneDeviceRefused, unless tenant's
// device id has an active record whose identity key (SPKI DER, X25519) is
// peerKey, the static key the phone's Noise session authenticated.
func checkPhoneDevice(ctx context.Context, reg *devicereg.Registry, tenant, id string, peerKey []byte) error {
	device, err := reg.Get(ctx, tenant, id)
	if err != nil {
		return errors.Join(ErrPhoneDeviceRefused, err)
	}
	if !device.Active() {
		return fmt.Errorf("%w: device %q is revoked", ErrPhoneDeviceRefused, device.ID)
	}
	pub, err := x509.ParsePKIXPublicKey(device.IdentityKey)
	if err != nil {
		return fmt.Errorf("%w: device %q identity key: %v", ErrPhoneDeviceRefused, device.ID, err)
	}
	key, ok := pub.(*ecdh.PublicKey)
	if !ok || key.Curve() != ecdh.X25519() || len(peerKey) == 0 ||
		subtle.ConstantTimeCompare(key.Bytes(), peerKey) != 1 {
		return fmt.Errorf("%w: device %q identity key is not the session peer's key", ErrPhoneDeviceRefused, device.ID)
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
