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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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
)

// pivErrorToGRPC maps PIV domain errors to gRPC status codes.
var pivErrorToGRPC = map[error]codes.Code{
	xkms.ErrPIVNotInitialized:   codes.FailedPrecondition,
	xkms.ErrPIVBackendNotFound:  codes.NotFound,
	xkms.ErrPIVInvalidAlgorithm: codes.InvalidArgument,
	xkms.ErrPIVInvalidSlot:      codes.InvalidArgument,
	xkms.ErrPIVInvalidFormat:    codes.InvalidArgument,
	xkms.ErrPIVKeyNotFound:      codes.NotFound,
}

// mapPIVError converts a PIV domain error to the appropriate gRPC status error.
// If the error is a known PIV error, it maps to the corresponding gRPC code.
// Otherwise, it returns an Internal error.
func mapPIVError(err error, operation string) error {
	if err == nil {
		return nil
	}

	for pivErr, code := range pivErrorToGRPC {
		if errors.Is(err, pivErr) {
			return status.Errorf(code, "%s: %v", operation, err)
		}
	}

	return status.Errorf(codes.Internal, "%s: %v", operation, err)
}

// ListPIVSlots returns the status of all PIV slots for the specified backend.
func (s *Service) ListPIVSlots(ctx context.Context, req *pb.ListPIVSlotsRequest) (*pb.ListPIVSlotsResponse, error) {
	if req.GetBackend() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrPIVBackendRequired.Error())
	}

	if err := s.authorize(ctx, "piv", "read", req.GetBackend()); err != nil {
		return nil, err
	}

	tReq := &transport.ListPIVSlotsRequest{
		Backend: req.GetBackend(),
	}

	resp, err := xkms.ListPIVSlots(ctx, tReq)
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

	if err := s.authorize(ctx, "piv", "read", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GetPIVCertificateRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
		Format:  req.GetFormat(),
	}

	resp, err := xkms.GetPIVCertificate(ctx, tReq)
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

	if err := s.authorize(ctx, "piv", "write", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.StorePIVCertificateRequest{
		Backend:     req.GetBackend(),
		Slot:        req.GetSlot(),
		Certificate: req.GetCertificate(),
		Format:      req.GetFormat(),
	}

	if err := xkms.StorePIVCertificate(ctx, tReq); err != nil {
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

	if err := s.authorize(ctx, "piv", "delete", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.DeletePIVCertificateRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
	}

	if err := xkms.DeletePIVCertificate(ctx, tReq); err != nil {
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

	if err := s.authorize(ctx, "piv", "write", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GeneratePIVKeyRequest{
		Backend:   req.GetBackend(),
		Slot:      req.GetSlot(),
		Algorithm: req.GetAlgorithm(),
		Subject:   req.GetSubject(),
	}

	resp, err := xkms.GeneratePIVKey(ctx, tReq)
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

	if err := s.authorize(ctx, "piv", "write", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.StorePIVCertificateRequest{
		Backend:     req.GetBackend(),
		Slot:        req.GetSlot(),
		Certificate: req.GetCertificate(),
		Format:      req.GetFormat(),
	}

	if err := xkms.ImportPIVCertificate(ctx, tReq); err != nil {
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

	if err := s.authorize(ctx, "piv", "read", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GetPIVCertificateRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
		Format:  req.GetFormat(),
	}

	resp, err := xkms.ExportPIVCertificate(ctx, tReq)
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

	if err := s.authorize(ctx, "piv", "use", req.GetSlot()); err != nil {
		return nil, err
	}

	tReq := &transport.GeneratePIVCSRRequest{
		Backend: req.GetBackend(),
		Slot:    req.GetSlot(),
		Subject: req.GetSubject(),
	}

	resp, err := xkms.GeneratePIVCSR(ctx, tReq)
	if err != nil {
		return nil, mapPIVError(err, "generate piv csr")
	}

	return &pb.GeneratePIVCSRResponse{
		Slot: resp.Slot,
		Csr:  resp.CSR,
	}, nil
}
