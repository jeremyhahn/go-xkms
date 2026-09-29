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

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// keyImporter is the import capability at the Backend layer: the operational
// surface of backend.ImportBackend without its embedded types.KeyProvider. It
// exists so a Backend wrapper can offer the capability itself --
// TenantScopedBackend cannot satisfy backend.ImportBackend because
// Backend.RotateKey and types.KeyProvider.RotateKey share a name with
// different signatures, and GenerateRSA/GenerateECDSA/GenerateEd25519 have no
// KeyProvider.GenerateKey equivalent at all -- and it must not be reached
// through KeyProvider(), which returns the base provider and discards the
// wrapper along with the tenant it stamps (go-xkms#163).
//
// Every backend.ImportBackend satisfies this interface, so an unscoped
// Backend's provider is used through it exactly as it always was.
type keyImporter interface {
	// GetImportParameters retrieves the parameters needed to import a key.
	// See backend.ImportBackend.GetImportParameters.
	GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error)

	// WrapKey wraps key material for secure transport.
	// See backend.ImportBackend.WrapKey.
	WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)

	// UnwrapKey unwraps key material previously wrapped with WrapKey.
	// See backend.ImportBackend.UnwrapKey.
	UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error)

	// ImportKey imports externally generated key material.
	// See backend.ImportBackend.ImportKey.
	ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error
}

// keyExporter is the export capability at the Backend layer: the operational
// surface of backend.ExportBackend without its embedded types.KeyProvider,
// for the same reason keyImporter exists apart from backend.ImportBackend.
type keyExporter interface {
	// ExportKey exports a key in wrapped form for secure transport.
	// See backend.ExportBackend.ExportKey.
	ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error)

	// ExportKeyTo exports a key wrapped for a destination's own import
	// parameters. See backend.ExportBackend.ExportKeyTo.
	ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)

	// ExportKeyMaterial returns raw key material for extractable symmetric
	// keys. See backend.ExportBackend.ExportKeyMaterial.
	ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error)
}

// Compile-time checks: each capability is a strict subset of its
// backend.ImportBackend / backend.ExportBackend counterpart, so every
// provider that implements the full interface is usable wherever the
// capability is asked for.
var (
	_ keyImporter = (backend.ImportBackend)(nil)
	_ keyExporter = (backend.ExportBackend)(nil)
)

// Compile-time checks: the tenant wrapper offers each capability itself,
// which is the point -- reaching import or export through KeyProvider()
// would discard it.
var (
	_ keyImporter = (*TenantScopedBackend)(nil)
	_ keyExporter = (*TenantScopedBackend)(nil)
)

// importBackendFor resolves b's import capability without discarding tenant
// scoping.
//
// A TenantScopedBackend provides the capability itself, stamping the tenant
// on every attribute set exactly as its other key operations do -- but only
// when its base actually supports import, so a caller that probes the
// capability gets the same answer scoped as unscoped. Every other Backend
// resolves through its KeyProvider, exactly as every call site always has.
//
// This asserts backend.ImportBackend on its own, never the union of import
// and export: a backend that only supports one direction -- AWS KMS is the
// canonical hardware example -- must be reachable for the half it does
// support regardless of the other.
func importBackendFor(b Backend) (keyImporter, bool) {
	if t, ok := b.(*TenantScopedBackend); ok {
		if _, baseOK := importBackendFor(t.base); !baseOK {
			return nil, false
		}
		return t, true
	}
	if importer, ok := b.KeyProvider().(backend.ImportBackend); ok {
		return importer, true
	}
	return nil, false
}

// exportBackendFor resolves b's export capability without discarding tenant
// scoping. See importBackendFor's doc comment; this is its export-side
// mirror, asserting backend.ExportBackend on its own.
func exportBackendFor(b Backend) (keyExporter, bool) {
	if t, ok := b.(*TenantScopedBackend); ok {
		if _, baseOK := exportBackendFor(t.base); !baseOK {
			return nil, false
		}
		return t, true
	}
	if exporter, ok := b.KeyProvider().(backend.ExportBackend); ok {
		return exporter, true
	}
	return nil, false
}
