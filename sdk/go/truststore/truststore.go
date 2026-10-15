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

// Package truststore is the SDK re-export of the attestation trust store
// (pkg/attestation/truststore). Client binaries import this package instead
// of pkg/* so they depend only on the SDK.
package truststore

import (
	"github.com/jeremyhahn/go-xkms/pkg/attestation/truststore"
)

const (
	PurposeGeneral         = truststore.PurposeGeneral
	PurposeTPMManufacturer = truststore.PurposeTPMManufacturer
	PurposeAndroidHardware = truststore.PurposeAndroidHardware
	PurposeUserCA          = truststore.PurposeUserCA
	PurposeBootstrapCA     = truststore.PurposeBootstrapCA
	PurposeIDevIDIssuer    = truststore.PurposeIDevIDIssuer
	PurposeImageSigner     = truststore.PurposeImageSigner
	PurposeSynced          = truststore.PurposeSynced
)

type (
	AddCertificateOptions = truststore.AddCertificateOptions
	CertPurpose           = truststore.CertPurpose
	FileStore             = truststore.FileStore
	FileStoreConfig       = truststore.FileStoreConfig
	ImportResult          = truststore.ImportResult
	TrustStore            = truststore.TrustStore
)

var (
	BootstrapImportOptions = truststore.BootstrapImportOptions
	Fingerprint            = truststore.Fingerprint
	IsAnchorPurpose        = truststore.IsAnchorPurpose
	IsValidPurpose         = truststore.IsValidPurpose
	LoadEmbeddedRoots      = truststore.LoadEmbeddedRoots
	NewBackendStore        = truststore.NewBackendStore
	NewFileStore           = truststore.NewFileStore
	NewOSCertStore         = truststore.NewOSCertStore
	ParsePurpose           = truststore.ParsePurpose

	ErrCertificateExists   = truststore.ErrCertificateExists
	ErrCertificateNotFound = truststore.ErrCertificateNotFound
)
