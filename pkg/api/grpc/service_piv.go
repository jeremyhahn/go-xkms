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

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// Typed errors for PIV gRPC operations.
var (
	// ErrPIVBackendRequired is returned when the backend field is missing.
	ErrPIVBackendRequired = errors.New("grpc: piv backend is required")

	// ErrPIVSlotRequired is returned when the slot field is missing.
	ErrPIVSlotRequired = errors.New("grpc: piv slot is required")

	// ErrPIVFormatRequired is returned when the format field is missing.
	ErrPIVFormatRequired = errors.New("grpc: piv certificate format is required")

	// ErrPIVCertificateRequired is returned when the certificate data is missing.
	ErrPIVCertificateRequired = errors.New("grpc: piv certificate data is required")

	// ErrPIVServiceNotConfigured is returned when no XKMSService is composed
	// to serve the PIV RPCs.
	ErrPIVServiceNotConfigured = errors.New("grpc: piv service not configured")
)

// The PIV RPCs delegate to the XKMSService's PIV methods: the PIV card is the
// server's own hardware, and the service's system-tenant check is what
// refuses a tenant-scoped caller (go-xkms#1227).

// mapPIVError converts a PIV domain error to the appropriate gRPC status
// error, classifying it through apierrors.PIVSentinelClasses -- the table
// go-xkms#912 made this package share with pkg/api/mcp's mirror of this
// function. If the error is a known PIV error, it maps to the corresponding
// gRPC code. Otherwise, it returns an Internal error.
func mapPIVError(err error, operation string) error {
	if err == nil {
		return nil
	}

	if class, ok := apierrors.ClassOf(apierrors.PIVSentinelClasses, err); ok {
		return status.Errorf(grpcCodeForClass(class), "%s: %v", operation, err)
	}

	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// ListPIVSlots returns the status of all PIV slots for the specified backend.
func (s *Service) ListPIVSlots(ctx context.Context, req *pb.ListPIVSlotsRequest) (*pb.ListPIVSlotsResponse, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionRead, req.GetBackend()); err != nil {
		return nil, err
	}

	tReq := &transport.ListPIVSlotsRequest{
		Backend: req.GetBackend(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	resp, err := s.xkmsService.ListPIVSlots(ctx, tReq)
	if err != nil {
		return nil, mapPIVError(err, "list piv slots")
	}

	pbSlots := make([]*pb.PIVSlotStatus, len(resp.Slots))
	for i, slot := range resp.Slots {
		pbSlots[i] = &pb.PIVSlotStatus{
			Slot:        slot.Slot,
			Name:        slot.Name,
			Description: slot.Description,
			HasCert:     slot.HasCert,
			Subject:     slot.Subject,
			Algorithm:   slot.Algorithm,
			KeySize:     int32(slot.KeySize), // #nosec G115 - Key size fits in int32
			NotAfter:    slot.NotAfter,
			Fingerprint: slot.Fingerprint,
		}
	}

	return &pb.ListPIVSlotsResponse{
		Slots: pbSlots,
	}, nil
}

// GetPIVCertificate retrieves a certificate from a PIV slot.
func (s *Service) GetPIVCertificate(ctx context.Context, req *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}
	if req.GetFormat() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVFormatRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionRead, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GetPIVCertificateRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
		Format:  req.GetFormat(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	resp, err := s.xkmsService.GetPIVCertificate(ctx, tReq)
	if err != nil {
		return nil, mapPIVError(err, "get piv certificate")
	}

	return &pb.GetPIVCertificateResponse{
		Slot:        resp.Slot,
		Certificate: resp.Certificate,
		Format:      resp.Format,
	}, nil
}

// StorePIVCertificate stores a certificate in a PIV slot.
func (s *Service) StorePIVCertificate(ctx context.Context, req *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}
	if req.GetFormat() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVFormatRequired.Error())
	}
	if len(req.GetCertificate()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrPIVCertificateRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionWrite, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.StorePIVCertificateRequest{
		Backend:     req.GetBackend(),
		Slot:        req.GetSlot(),
		Certificate: req.GetCertificate(),
		Format:      req.GetFormat(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	if err := s.xkmsService.StorePIVCertificate(ctx, tReq); err != nil {
		return nil, mapPIVError(err, "store piv certificate")
	}

	return &emptypb.Empty{}, nil
}

// DeletePIVCertificate removes a certificate from a PIV slot.
func (s *Service) DeletePIVCertificate(ctx context.Context, req *pb.DeletePIVCertificateRequest) (*emptypb.Empty, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionDelete, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.DeletePIVCertificateRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	if err := s.xkmsService.DeletePIVCertificate(ctx, tReq); err != nil {
		return nil, mapPIVError(err, "delete piv certificate")
	}

	return &emptypb.Empty{}, nil
}

// GeneratePIVKey generates a new key pair in a PIV slot with a self-signed certificate.
func (s *Service) GeneratePIVKey(ctx context.Context, req *pb.GeneratePIVKeyRequest) (*pb.GeneratePIVKeyResponse, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionWrite, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GeneratePIVKeyRequest{
		Backend:   req.GetBackend(),
		Slot:      req.GetSlot(),
		Algorithm: req.GetAlgorithm(),
		Subject:   req.GetSubject(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	resp, err := s.xkmsService.GeneratePIVKey(ctx, tReq)
	if err != nil {
		return nil, mapPIVError(err, "generate piv key")
	}

	return &pb.GeneratePIVKeyResponse{
		Slot:        resp.Slot,
		Certificate: resp.Certificate,
		PublicKey:   resp.PublicKey,
	}, nil
}

// ImportPIVCertificate imports a certificate into a PIV slot.
func (s *Service) ImportPIVCertificate(ctx context.Context, req *pb.StorePIVCertificateRequest) (*emptypb.Empty, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}
	if req.GetFormat() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVFormatRequired.Error())
	}
	if len(req.GetCertificate()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrPIVCertificateRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionWrite, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.StorePIVCertificateRequest{
		Backend:     req.GetBackend(),
		Slot:        req.GetSlot(),
		Certificate: req.GetCertificate(),
		Format:      req.GetFormat(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	if err := s.xkmsService.ImportPIVCertificate(ctx, tReq); err != nil {
		return nil, mapPIVError(err, "import piv certificate")
	}

	return &emptypb.Empty{}, nil
}

// ExportPIVCertificate exports a certificate from a PIV slot.
func (s *Service) ExportPIVCertificate(ctx context.Context, req *pb.GetPIVCertificateRequest) (*pb.GetPIVCertificateResponse, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}
	if req.GetFormat() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVFormatRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionRead, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GetPIVCertificateRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
		Format:  req.GetFormat(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	resp, err := s.xkmsService.ExportPIVCertificate(ctx, tReq)
	if err != nil {
		return nil, mapPIVError(err, "export piv certificate")
	}

	return &pb.GetPIVCertificateResponse{
		Slot:        resp.Slot,
		Certificate: resp.Certificate,
		Format:      resp.Format,
	}, nil
}

// GeneratePIVCSR generates a certificate signing request for a PIV slot key.
func (s *Service) GeneratePIVCSR(ctx context.Context, req *pb.GeneratePIVCSRRequest) (*pb.GeneratePIVCSRResponse, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}
	if req.GetSlot() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVSlotRequired.Error())
	}

	if err := s.authorize(ctx, auth.ResourcePIV, auth.ActionUse, req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GeneratePIVCSRRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
		Subject: req.GetSubject(),
	}

	if s.xkmsService == nil {
		return nil, status.Error(codes.Unavailable, ErrPIVServiceNotConfigured.Error())
	}
	resp, err := s.xkmsService.GeneratePIVCSR(ctx, tReq)
	if err != nil {
		return nil, mapPIVError(err, "generate piv csr")
	}

	return &pb.GeneratePIVCSRResponse{
		Slot: resp.Slot,
		Csr:  resp.CSR,
	}, nil
}
