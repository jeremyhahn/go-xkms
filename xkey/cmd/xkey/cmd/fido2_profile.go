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

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// FIDO2 profile storage layout. The profile lives beside the per-RP policies
// under the FIDO2 storage path so a Security Officer's authenticator policy is
// kept in one place.
const (
	// fido2ProfileStoreSubdir is the directory, relative to the configured
	// FIDO2 storage path, that holds the authenticator profile.
	fido2ProfileStoreSubdir = "fido2-profile"

	// fido2ProfileKey is the storage key of the single profile document
	// within the profile store directory.
	fido2ProfileKey = "profile"
)

// FIDO2 profile errors.
var (
	// ErrFIDO2ProfileStoreOpenFailed indicates the profile store could not be opened.
	ErrFIDO2ProfileStoreOpenFailed = errors.New("fido2 profile: failed to open the profile store")

	// ErrFIDO2ProfileSaveFailed indicates the profile could not be persisted.
	ErrFIDO2ProfileSaveFailed = errors.New("fido2 profile: failed to save the profile")

	// ErrFIDO2ProfileLoadFailed indicates the persisted profile could not be read.
	ErrFIDO2ProfileLoadFailed = errors.New("fido2 profile: failed to load the profile")

	// ErrFIDO2ProfileEncodeFailed indicates the profile could not be encoded.
	ErrFIDO2ProfileEncodeFailed = errors.New("fido2 profile: failed to encode the profile")

	// ErrFIDO2ProfileDecodeFailed indicates the stored profile is not valid JSON.
	ErrFIDO2ProfileDecodeFailed = errors.New("fido2 profile: stored profile is corrupt")

	// ErrFIDO2ProfileNoSettings indicates no profile setting was supplied.
	ErrFIDO2ProfileNoSettings = errors.New("fido2 profile: specify at least one setting (--transports or --enterprise-attestation)")
)

// FIDO2Profile is the persisted authenticator profile: the Security
// Officer-controlled settings that shape the CTAP2 GetInfo response the
// authenticator returns to relying parties.
type FIDO2Profile struct {
	// Transports is the transports list advertised in GetInfo (key 0x09).
	// An empty list means the authenticator's built-in default ("usb").
	Transports []string `json:"transports,omitempty"`

	// EnterpriseAttestation advertises the "ep" option in GetInfo.
	EnterpriseAttestation bool `json:"enterprise_attestation"`
}

// Validate rejects a profile that names an unknown transport.
func (p *FIDO2Profile) Validate() error {
	for _, transport := range p.Transports {
		if !fido2ValidTransports[transport] {
			return &DetailError{Err: ErrFIDO2ProfileInvalidTransport, Detail: ": " + transport}
		}
	}
	return nil
}

// fido2ProfileStorePath returns the directory holding the persisted profile.
// It hangs off the configured FIDO2 storage path (resolveFIDO2StoragePath,
// fido2.go) so the profile shares the lifetime of the authenticator's other
// on-disk policy -- and, when no --storage-path was set, the same resolved
// xkey data directory rather than a cwd-relative default (go-xkms#929).
func fido2ProfileStorePath(cfg *FIDO2Config) (string, error) {
	base, err := resolveFIDO2StoragePath(cfg)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, fido2ProfileStoreSubdir), nil
}

// openFIDO2ProfileStore opens the file-backed store holding the
// authenticator profile, creating the directory when it does not exist.
//
// The profile is always file-backed, even when the authenticator itself runs
// with memory credential storage: a profile that vanished with the process
// could never influence a later GetInfo response.
func openFIDO2ProfileStore(cfg *FIDO2Config) (xkms.StorageBackend, error) {
	path, err := fido2ProfileStorePath(cfg)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2ProfileStoreOpenFailed, Cause: err}
	}
	backend, err := xkms.NewFileStorageBackend(path)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2ProfileStoreOpenFailed, Cause: err}
	}
	return backend, nil
}

// saveFIDO2Profile persists the profile, replacing any previous document.
func saveFIDO2Profile(ctx context.Context, cfg *FIDO2Config, profile *FIDO2Profile) (err error) {
	if err := profile.Validate(); err != nil {
		return err
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrFIDO2ProfileEncodeFailed, Cause: err}
	}

	backend, err := openFIDO2ProfileStore(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := backend.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if err := backend.Put(ctx, fido2ProfileKey, data); err != nil {
		return &SentinelCauseError{Sentinel: ErrFIDO2ProfileSaveFailed, Cause: err}
	}
	return nil
}

// loadFIDO2Profile reads the persisted profile. A store that has never been
// written yields the zero profile, which is the authenticator's default
// behavior, so callers do not special-case first use.
func loadFIDO2Profile(ctx context.Context, cfg *FIDO2Config) (_ *FIDO2Profile, err error) {
	backend, err := openFIDO2ProfileStore(cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := backend.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	data, err := backend.Get(ctx, fido2ProfileKey)
	if err != nil {
		if errors.Is(err, xkms.ErrStorageNotFound) {
			return &FIDO2Profile{}, nil
		}
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2ProfileLoadFailed, Cause: err}
	}

	profile := &FIDO2Profile{}
	if err := json.Unmarshal(data, profile); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrFIDO2ProfileDecodeFailed, Cause: err}
	}
	return profile, nil
}
