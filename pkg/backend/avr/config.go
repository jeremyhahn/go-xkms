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

package avr

import (
	"log/slog"
	"os"
	"time"

	aggeneric "github.com/jeremyhahn/trusted-firmware/sdk/go"
)

const (
	// DefaultKeyCN is the common name the device's identity key is addressed
	// by when Config does not name one.
	DefaultKeyCN = "avr-device-id"

	// DefaultRequestTimeout bounds one command.
	//
	// Generous on purpose, and for the SDK's own reason: a device deriving a
	// key in software spends seconds inside one command on a 16 MHz part, and
	// a host that gave up after the usual serial timeout would declare a
	// working device dead at exactly the moment it was proving itself.
	DefaultRequestTimeout = 30 * time.Second
)

// Config configures the AVR backend.
type Config struct {
	// KeyCN is the common name the device's identity key is addressed by.
	// Defaults to DefaultKeyCN. An AVR device holds exactly one key, so this
	// is the only name GetKey and Signer will answer to.
	KeyCN string `yaml:"key_cn" json:"key_cn"`

	// Slot is the element slot holding the identity keypair. It defaults to
	// aggeneric.SlotDeviceID and there is no reason to set it otherwise: the
	// assignment is compiled into the firmware and into the element's locked
	// configuration zone, so a host that disagrees is simply wrong about a
	// part it cannot correct.
	Slot uint8 `yaml:"slot" json:"slot"`

	// RequestTimeout bounds one command against the device. Zero selects
	// DefaultRequestTimeout.
	RequestTimeout time.Duration `yaml:"request_timeout" json:"request_timeout"`

	// Attestation configures what an alias certificate must prove. Nil is the
	// unanchored profile: AttestKey still checks the challenge, the curve and
	// the signature algorithm, and reports Anchored false.
	Attestation *AttestationConfig `yaml:"attestation" json:"attestation"`

	// Logger is the structured logger. Zero selects a stderr text logger.
	Logger *slog.Logger `yaml:"-" json:"-"`
}

// DefaultConfig returns a Config addressing the identity key of an ordinary
// device.
func DefaultConfig() *Config {
	return &Config{
		KeyCN:          DefaultKeyCN,
		Slot:           aggeneric.SlotDeviceID,
		RequestTimeout: DefaultRequestTimeout,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	}
}

// Validate checks the configuration and fills in defaults for the fields whose
// zero value is a request for one.
//
// KeyCN is the exception: the empty string is refused rather than defaulted,
// because it is indistinguishable from a caller that forgot to set it and
// would then match every KeyAttributes with no common name.
func (c *Config) Validate() error {
	if c.KeyCN == "" {
		return ErrMissingKeyCN
	}
	if c.Slot != aggeneric.SlotDeviceID {
		return ErrInvalidSlot
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return nil
}
