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

import qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

// --- Backup/restore types aliased from go-qrdb (owner ruling 2026-09-30,
// go-xkms#728) ---
//
// Whole-node backup captures a point-in-time shard snapshot of the embedded
// go-qrdb node's barrier-encrypted, replicated state. xkms persists no
// backup state and performs no snapshot logic of its own; every type here is
// a direct alias of go-qrdb's own wire shape, so a backup created through
// xkms and one created through qrdb's own API describe themselves
// identically.

// CompressionType identifies the compression algorithm applied to a backup.
type CompressionType = qrdbtransport.CompressionType

// EncryptionType identifies the encryption algorithm applied to a backup.
type EncryptionType = qrdbtransport.EncryptionType

// BackupStatus describes the current state of a backup.
type BackupStatus = qrdbtransport.BackupStatus

// BackupRequest contains options for creating a backup.
type BackupRequest = qrdbtransport.BackupRequest

// BackupInfo contains metadata about a completed or in-progress backup.
type BackupInfo = qrdbtransport.BackupInfo

// RestoreRequest contains options for restoring from a backup.
type RestoreRequest = qrdbtransport.RestoreRequest

// RestoreResult describes the outcome of a restore operation.
type RestoreResult = qrdbtransport.RestoreResult

// ShardError describes a per-shard error during backup or restore.
type ShardError = qrdbtransport.ShardError

// VerifyResult describes the outcome of a backup verification.
type VerifyResult = qrdbtransport.VerifyResult

// ListBackupsResponse holds the list of backups returned by a list operation.
type ListBackupsResponse = qrdbtransport.ListBackupsResponse

// Backup compression constants, re-exported verbatim.
const (
	CompressionNone   = qrdbtransport.CompressionNone
	CompressionZstd   = qrdbtransport.CompressionZstd
	CompressionSnappy = qrdbtransport.CompressionSnappy
)

// Backup encryption constants, re-exported verbatim.
const (
	EncryptionNone   = qrdbtransport.EncryptionNone
	EncryptionAES256 = qrdbtransport.EncryptionAES256
)

// Backup status constants, re-exported verbatim.
const (
	BackupStatusPending  = qrdbtransport.BackupStatusPending
	BackupStatusRunning  = qrdbtransport.BackupStatusRunning
	BackupStatusComplete = qrdbtransport.BackupStatusComplete
	BackupStatusFailed   = qrdbtransport.BackupStatusFailed
)
