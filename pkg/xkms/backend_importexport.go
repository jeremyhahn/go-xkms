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

// ImportExporter is the import/export capability at the Backend layer: the
// operational surface of backend.ImportExportBackend without its embedded
// types.KeyProvider. It exists so a Backend wrapper can offer the capability
// itself — TenantScopedBackend cannot satisfy backend.ImportExportBackend
// because Backend.RotateKey and types.KeyProvider.RotateKey share a name with
// different signatures, and it must not be reached through KeyProvider(),
// which returns the base provider and discards the wrapper along with the
// tenant it stamps (go-xkms#163).
//
// Every backend.ImportExportBackend satisfies this interface, so an unscoped
// Backend's provider is used through it exactly as it always was.
type ImportExporter interface {
	// GetImportParameters retrieves the parameters needed to import a key.
	// See backend.ImportExportBackend.GetImportParameters.
	GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error)

	// WrapKey wraps key material for secure transport.
	// See backend.ImportExportBackend.WrapKey.
	WrapKey(ctx context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)

	// UnwrapKey unwraps key material previously wrapped with WrapKey.
	// See backend.ImportExportBackend.UnwrapKey.
	UnwrapKey(ctx context.Context, wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error)

	// ImportKey imports externally generated key material.
	// See backend.ImportExportBackend.ImportKey.
	ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error

	// ExportKey exports a key in wrapped form for secure transport.
	// See backend.ImportExportBackend.ExportKey.
	ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error)

	// ExportKeyTo exports a key wrapped for a destination's own import
	// parameters. See backend.ExportBackend.ExportKeyTo.
	ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)

	// ExportKeyMaterial returns raw key material for extractable symmetric
	// keys. See backend.ImportExportBackend.ExportKeyMaterial.
	ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error)
}

// Compile-time check: the capability is a strict subset of
// backend.ImportExportBackend, so every provider that implements the full
// interface is usable wherever the capability is asked for.
var _ ImportExporter = (backend.ImportExportBackend)(nil)

// Compile-time check: the tenant wrapper offers the capability itself, which
// is the point — reaching import through KeyProvider() would discard it.
var _ ImportExporter = (*TenantScopedBackend)(nil)

// importExportFor resolves b's import/export capability without discarding
// tenant scoping.
//
// A TenantScopedBackend provides the capability itself, stamping the tenant
// on every attribute set exactly as its other key operations do — but only
// when its base actually supports import/export, so a caller that probes the
// capability gets the same answer scoped as unscoped. Every other Backend
// resolves through its KeyProvider, exactly as every call site always has.
func importExportFor(b Backend) (ImportExporter, bool) {
	if t, ok := b.(*TenantScopedBackend); ok {
		if _, baseOK := importExportFor(t.base); !baseOK {
			return nil, false
		}
		return t, true
	}
	if importExport, ok := b.KeyProvider().(backend.ImportExportBackend); ok {
		return importExport, true
	}
	return nil, false
}
