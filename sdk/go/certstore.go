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

import "github.com/jeremyhahn/go-xkms/pkg/certstore"

// Certificate-store surface re-exported so the xkey GUI/CLI use the canonical
// pkg/certstore interface and certificate-formatting helpers through the SDK.
// The CertStore interface and a number of related types (CertStoreConfig,
// ChainInfo, CRLEntry, ...) are already aliased in storage.go; the symbols here
// add the X.509 stringer helpers (the CertStore interface is in storage.go).

// CertStore.ToString is already aliased as CertToString in storage.go.

// ExtKeyUsageToString renders an x509.ExtKeyUsage as a string.
var ExtKeyUsageToString = certstore.ExtKeyUsageToString

// KeyUsageToString renders an x509.KeyUsage as a string.
var KeyUsageToString = certstore.KeyUsageToString

// OIDToName maps an ASN.1 object identifier to a human-readable name.
var OIDToName = certstore.OIDToName

// PublicKeyTypeString renders a public key's algorithm/size as a string.
var PublicKeyTypeString = certstore.PublicKeyTypeString

// ParseCertExtensionValue renders a certificate extension's value as a string.
var ParseCertExtensionValue = certstore.ParseExtensionValue

// ParseTCGCertAttributes extracts TCG attestation attributes from a certificate.
var ParseTCGCertAttributes = certstore.ParseTCGAttributes
