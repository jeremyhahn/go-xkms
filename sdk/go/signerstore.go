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

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/signing/store"

// Signer-store surface re-exported so an SDK-only consumer can implement the
// full ServiceBackend contract, whose SignerStore method returns a
// SignerStorer -- for example the backends a TrustedCAKeyStoreFactoryFunc
// returns. NewSignerStore takes the DAO factory NewBackendDAOFactory (or an
// open Datastore's DAOFactory) yields.

// SignerStorer persists crypto.Signer key material and per-blob signatures.
type SignerStorer = store.SignerStorer

// SignerStoreOpts identifies the signing key and blob of a persisted
// signature record. It is distinct from SignerOpts, the signing options.
type SignerStoreOpts = store.SignerOpts

// NewSignerStore opens the signer store over a DAO factory.
var NewSignerStore = store.NewSignerStore

// ErrSignerStoreNilDAOFactory is returned by NewSignerStore without a DAO
// factory.
var ErrSignerStoreNilDAOFactory = store.ErrNilDAOFactory

// ErrSignatureNotFound is returned by SignerStorer.GetSignature when no
// record exists for the requested key and blob.
type ErrSignatureNotFound = store.ErrSignatureNotFound
