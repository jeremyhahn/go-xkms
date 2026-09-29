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

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/api/apierrors"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// The sealStore.* handlers are the MCP server side of the machine-local
// sealed credential store. They gate on the keys resource, matching the
// gRPC/REST/Unix SealStore* handlers, since all persist key-protection
// material sealed to the host's hardware.

// ErrSealStoreNotConfigured is returned when no platform-sealed store is
// wired into the server.
var ErrSealStoreNotConfigured = xkms.ErrNotConfigured

// mapSealStoreError converts an error from the platform-sealed store into a
// *KeyOpError, classifying it through apierrors.SealStoreSentinelClasses --
// the table go-xkms#921 made this package share with
// pkg/api/grpc/service_seal_store.go's mapSealStoreError -- so a capability
// refusal never surfaces to InvokeMethod's dispatcher as ErrCodeInternalError.
// Anything not in that table is an internal fault. It also classifies
// ErrSealStoreNotConfigured, the sentinel each handler below returns when no
// xkms service is wired in, matching gRPC's "xkms service not initialized"
// Unavailable status for the same condition.
func mapSealStoreError(err error) error {
	if err == nil {
		return nil
	}
	if class, ok := apierrors.ClassOf(apierrors.SealStoreSentinelClasses, err); ok {
		return classified(jsonRPCCodeForClass(class), err)
	}
	return &KeyOpError{Code: ErrCodeInternalError, Err: err}
}

// handleSealStorePut handles the sealStore.put method.
func (s *Server) handleSealStorePut(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapSealStoreError(ErrSealStoreNotConfigured)
	}
	var params transport.SealStorePutRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.SealStorePut(ctx, &params); err != nil {
		return nil, mapSealStoreError(err)
	}
	return map[string]string{"name": params.Name}, nil
}

// handleSealStoreGet handles the sealStore.get method.
func (s *Server) handleSealStoreGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapSealStoreError(ErrSealStoreNotConfigured)
	}
	var params transport.SealStoreGetRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.SealStoreGet(ctx, &params)
	if err != nil {
		return nil, mapSealStoreError(err)
	}
	return resp, nil
}

// handleSealStoreDelete handles the sealStore.delete method.
func (s *Server) handleSealStoreDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapSealStoreError(ErrSealStoreNotConfigured)
	}
	var params transport.SealStoreDeleteRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.SealStoreDelete(ctx, &params); err != nil {
		return nil, mapSealStoreError(err)
	}
	return map[string]string{"name": params.Name}, nil
}

// handleSealStoreList handles the sealStore.list method.
func (s *Server) handleSealStoreList(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapSealStoreError(ErrSealStoreNotConfigured)
	}
	resp, err := s.xkmsService.SealStoreList(ctx)
	if err != nil {
		return nil, mapSealStoreError(err)
	}
	return resp, nil
}

// handleSealStoreReseal handles the sealStore.reseal method.
func (s *Server) handleSealStoreReseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapSealStoreError(ErrSealStoreNotConfigured)
	}
	var params transport.SealStoreResealRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.SealStoreReseal(ctx, &params); err != nil {
		return nil, mapSealStoreError(err)
	}
	return map[string]string{"name": params.Name}, nil
}

// handleSealStoreStatus handles the sealStore.status method.
func (s *Server) handleSealStoreStatus(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, mapSealStoreError(ErrSealStoreNotConfigured)
	}
	resp, err := s.xkmsService.SealStoreStatus(ctx)
	if err != nil {
		return nil, mapSealStoreError(err)
	}
	return resp, nil
}
