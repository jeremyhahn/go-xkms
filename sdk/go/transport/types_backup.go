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

package transport

import (
	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Backup/restore types (owner ruling 2026-09-30, go-xkms#728).
type CompressionType = pkgtransport.CompressionType
type EncryptionType = pkgtransport.EncryptionType
type BackupStatus = pkgtransport.BackupStatus
type BackupRequest = pkgtransport.BackupRequest
type BackupInfo = pkgtransport.BackupInfo
type RestoreRequest = pkgtransport.RestoreRequest
type RestoreResult = pkgtransport.RestoreResult
type ShardError = pkgtransport.ShardError
type VerifyResult = pkgtransport.VerifyResult
type ListBackupsResponse = pkgtransport.ListBackupsResponse

// Backup compression constants, re-exported verbatim.
const (
	CompressionNone   = pkgtransport.CompressionNone
	CompressionZstd   = pkgtransport.CompressionZstd
	CompressionSnappy = pkgtransport.CompressionSnappy
)

// Backup encryption constants, re-exported verbatim.
const (
	EncryptionNone   = pkgtransport.EncryptionNone
	EncryptionAES256 = pkgtransport.EncryptionAES256
)

// Backup status constants, re-exported verbatim.
const (
	BackupStatusPending  = pkgtransport.BackupStatusPending
	BackupStatusRunning  = pkgtransport.BackupStatusRunning
	BackupStatusComplete = pkgtransport.BackupStatusComplete
	BackupStatusFailed   = pkgtransport.BackupStatusFailed
)
