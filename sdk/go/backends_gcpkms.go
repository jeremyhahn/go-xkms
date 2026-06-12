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

//go:build gcpkms

package xkms

import gcpkmsbackend "github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"

// GCP Cloud KMS crypto backend re-exported behind the gcpkms build tag,
// matching the gating of pkg/backend/gcpkms. It conforms to the same
// Backend contract as the local backends.

// GCPKMSBackend is the GCP Cloud KMS crypto backend.
type GCPKMSBackend = gcpkmsbackend.Backend

// GCPKMSBackendConfig configures the GCP Cloud KMS crypto backend.
type GCPKMSBackendConfig = gcpkmsbackend.Config

// NewGCPKMSBackend constructs a GCP Cloud KMS crypto backend.
var NewGCPKMSBackend = gcpkmsbackend.NewBackend
