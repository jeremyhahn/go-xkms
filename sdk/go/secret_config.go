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

package xkms

import (
	qrdbsecret "github.com/jeremyhahn/go-qrdb/sdk/go/secret"
)

// Config-time secret-reference resolution, re-exported from go-qrdb's SPI
// (github.com/jeremyhahn/go-qrdb/sdk/go/secret) so consumers that only import
// the xkms SDK -- xkey among them -- can resolve a *SecretValue config field
// (e.g. a cloud KMS barrier strategy's explicit credential, go-xkms#757)
// through the SAME contract xkmsd resolves its own config secrets through
// (pkg/server/secret_wiring.go), rather than a locally invented scheme.

// SecretResolverRegistry dispatches secret resolution to the first
// registered resolver that claims a raw reference; an unclaimed reference is
// refused for a protected (*SecretValue) target rather than treated as a
// literal.
type SecretResolverRegistry = qrdbsecret.ResolverRegistry

// NewSecretResolverRegistry creates an empty SecretResolverRegistry. A
// consumer with no resolver of its own (xkey has no credential service)
// still uses this: every field left nil is ambient-credential (unconfigured)
// and never reaches resolution; a configured field with no resolver able to
// claim its reference fails with ErrUnresolvedSecretURI rather than being
// silently accepted.
var NewSecretResolverRegistry = qrdbsecret.NewResolverRegistry

// SecretConfigProcessor walks a config struct via reflection and resolves
// every *SecretValue field it reaches in place.
type SecretConfigProcessor = qrdbsecret.ConfigProcessor

// NewSecretConfigProcessor creates a SecretConfigProcessor backed by reg.
var NewSecretConfigProcessor = qrdbsecret.NewConfigProcessor

// SecretProcessResult summarises the outcome of a SecretConfigProcessor walk.
type SecretProcessResult = qrdbsecret.ProcessResult

// ErrUnresolvedSecretURI is returned by SecretConfigProcessor.Process when a
// protected *SecretValue target could not be resolved.
var ErrUnresolvedSecretURI = qrdbsecret.ErrUnresolvedSecretURI
