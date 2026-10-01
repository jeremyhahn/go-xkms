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

package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ==================== Backup Operations (go-xkms#728) ====================
//
// Whole-node backup/restore over the embedded go-qrdb node's shard-snapshot
// capability (owner ruling 2026-09-30). xkms performs no snapshot capture,
// checksum computation or encryption of its own; every RPC below is a direct
// pass-through to the node's BackupClient via the unified XKMSService.

// CreateBackup initiates a new backup with the specified options.
func (s *Service) CreateBackup(ctx context.Context, req *pb.BackupRequest) (*pb.BackupInfo, error) {
	if err := s.authorize(ctx, auth.ResourceBackup, auth.ActionCreate, "create-backup"); err != nil {
		return nil, err
	}
	if req.GetDestination() == "" {
		return nil, status.Error(codes.InvalidArgument, "destination is required")
	}

	resp, err := s.xkmsService.CreateBackup(ctx, &transport.BackupRequest{
		Destination:   req.GetDestination(),
		Compression:   transport.CompressionType(req.GetCompression()),
		Encryption:    transport.EncryptionType(req.GetEncryption()),
		EncryptionKey: req.GetEncryptionKey(),
		Metadata:      req.GetMetadata(),
		ShardIDs:      req.GetShardIds(),
	})
	if err != nil {
		return nil, mapBackupError(err, "create backup")
	}
	return backupInfoToProto(resp), nil
}

// ListBackups returns metadata for all available backups.
func (s *Service) ListBackups(ctx context.Context, _ *emptypb.Empty) (*pb.ListBackupsResponse, error) {
	if err := s.authorize(ctx, auth.ResourceBackup, auth.ActionList, "list-backups"); err != nil {
		return nil, err
	}

	backups, err := s.xkmsService.ListBackups(ctx)
	if err != nil {
		return nil, mapBackupError(err, "list backups")
	}

	out := make([]*pb.BackupInfo, len(backups))
	for i := range backups {
		out[i] = backupInfoToProto(&backups[i])
	}
	return &pb.ListBackupsResponse{Backups: out}, nil
}

// GetBackup returns metadata for a specific backup by ID.
func (s *Service) GetBackup(ctx context.Context, req *pb.GetBackupRequest) (*pb.BackupInfo, error) {
	if err := s.authorize(ctx, auth.ResourceBackup, auth.ActionRead, req.GetId()); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	resp, err := s.xkmsService.GetBackup(ctx, req.GetId())
	if err != nil {
		return nil, mapBackupError(err, "get backup")
	}
	return backupInfoToProto(resp), nil
}

// DeleteBackup removes a backup by ID.
func (s *Service) DeleteBackup(ctx context.Context, req *pb.DeleteBackupRequest) (*emptypb.Empty, error) {
	if err := s.authorize(ctx, auth.ResourceBackup, auth.ActionDelete, req.GetId()); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	if err := s.xkmsService.DeleteBackup(ctx, req.GetId()); err != nil {
		return nil, mapBackupError(err, "delete backup")
	}
	return &emptypb.Empty{}, nil
}

// RestoreBackup restores data from a backup, overwriting live shard state.
// It is gated by backup:restore, distinct from backup:create/backup:read,
// because it is the most destructive backup operation.
func (s *Service) RestoreBackup(ctx context.Context, req *pb.RestoreRequest) (*pb.RestoreResult, error) {
	if err := s.authorize(ctx, auth.ResourceBackup, auth.ActionRestore, req.GetBackupId()); err != nil {
		return nil, err
	}
	if req.GetBackupId() == "" {
		return nil, status.Error(codes.InvalidArgument, "backup_id is required")
	}

	resp, err := s.xkmsService.RestoreBackup(ctx, &transport.RestoreRequest{
		BackupID:      req.GetBackupId(),
		TargetShards:  req.GetTargetShards(),
		ValidateFirst: req.GetValidateFirst(),
		DecryptionKey: req.GetDecryptionKey(),
	})
	if err != nil {
		return nil, mapBackupError(err, "restore backup")
	}

	errs := make([]*pb.BackupShardError, len(resp.Errors))
	for i, e := range resp.Errors {
		errs[i] = &pb.BackupShardError{ShardId: e.ShardID, Message: e.Message}
	}
	return &pb.RestoreResult{
		BackupId:       resp.BackupID,
		ShardsRestored: int32(resp.ShardsRestored),
		DurationNs:     resp.Duration.Nanoseconds(),
		Errors:         errs,
	}, nil
}

// VerifyBackup verifies the integrity of a backup by computing and comparing
// checksums.
func (s *Service) VerifyBackup(ctx context.Context, req *pb.VerifyBackupRequest) (*pb.VerifyResult, error) {
	if err := s.authorize(ctx, auth.ResourceBackup, auth.ActionVerify, req.GetId()); err != nil {
		return nil, err
	}
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}

	resp, err := s.xkmsService.VerifyBackup(ctx, req.GetId())
	if err != nil {
		return nil, mapBackupError(err, "verify backup")
	}
	return &pb.VerifyResult{
		Valid:            resp.Valid,
		ChecksumMatch:    resp.ChecksumMatch,
		ExpectedChecksum: resp.ExpectedChecksum,
		ActualChecksum:   resp.ActualChecksum,
		Errors:           resp.Errors,
	}, nil
}

// backupInfoToProto converts a transport.BackupInfo to its wire form.
func backupInfoToProto(info *transport.BackupInfo) *pb.BackupInfo {
	return &pb.BackupInfo{
		Id:           info.ID,
		TimestampNs:  info.Timestamp.UnixNano(),
		Size:         info.Size,
		ShardCount:   int32(info.ShardCount),
		Status:       string(info.Status),
		Checksum:     info.Checksum,
		Destination:  info.Destination,
		Compression:  string(info.Compression),
		Encryption:   string(info.Encryption),
		Metadata:     info.Metadata,
		DurationNs:   info.Duration.Nanoseconds(),
		ErrorMessage: info.ErrorMessage,
	}
}

// mapBackupError maps backup domain errors (surfaced by the go-qrdb node's
// backup client) to gRPC status codes.
func mapBackupError(err error, op string) error {
	switch {
	case errors.Is(err, xkms.ErrNotConfigured):
		return status.Error(codes.FailedPrecondition, "backup service not configured")
	case errors.Is(err, xkms.ErrNilRequest):
		return status.Error(codes.InvalidArgument, err.Error())
	case isBackupNotFoundErr(err):
		return status.Errorf(codes.NotFound, "%s: %v", op, err)
	case isBackupEmptyFieldErr(err):
		return status.Errorf(codes.InvalidArgument, "%s: %v", op, err)
	case isBackupChecksumMismatchErr(err):
		return status.Errorf(codes.FailedPrecondition, "%s: %v", op, err)
	default:
		return status.Errorf(codes.Internal, "%s: %v", op, err)
	}
}

func isBackupNotFoundErr(err error) bool {
	var e *qrdbtransport.BackupNotFoundError
	return errors.As(err, &e)
}

func isBackupEmptyFieldErr(err error) bool {
	var dest *qrdbtransport.BackupEmptyDestinationError
	var id *qrdbtransport.BackupEmptyIDError
	return errors.As(err, &dest) || errors.As(err, &id)
}

func isBackupChecksumMismatchErr(err error) bool {
	var e *qrdbtransport.BackupChecksumMismatchError
	return errors.As(err, &e)
}
