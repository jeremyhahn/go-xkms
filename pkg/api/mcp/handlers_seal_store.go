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

// handleSealStorePut handles the sealStore.put method.
func (s *Server) handleSealStorePut(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, ErrSealStoreNotConfigured
	}
	var params transport.SealStorePutRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.SealStorePut(ctx, &params); err != nil {
		return nil, err
	}
	return map[string]string{"name": params.Name}, nil
}

// handleSealStoreGet handles the sealStore.get method.
func (s *Server) handleSealStoreGet(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, ErrSealStoreNotConfigured
	}
	var params transport.SealStoreGetRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	resp, err := s.xkmsService.SealStoreGet(ctx, &params)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleSealStoreDelete handles the sealStore.delete method.
func (s *Server) handleSealStoreDelete(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, ErrSealStoreNotConfigured
	}
	var params transport.SealStoreDeleteRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.SealStoreDelete(ctx, &params); err != nil {
		return nil, err
	}
	return map[string]string{"name": params.Name}, nil
}

// handleSealStoreList handles the sealStore.list method.
func (s *Server) handleSealStoreList(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, ErrSealStoreNotConfigured
	}
	resp, err := s.xkmsService.SealStoreList(ctx)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// handleSealStoreReseal handles the sealStore.reseal method.
func (s *Server) handleSealStoreReseal(ctx context.Context, req *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, ErrSealStoreNotConfigured
	}
	var params transport.SealStoreResealRequest
	if err := decodeParams(req, &params); err != nil {
		return nil, err
	}
	if err := s.xkmsService.SealStoreReseal(ctx, &params); err != nil {
		return nil, err
	}
	return map[string]string{"name": params.Name}, nil
}

// handleSealStoreStatus handles the sealStore.status method.
func (s *Server) handleSealStoreStatus(ctx context.Context, _ *JSONRPCRequest) (interface{}, error) {
	if s.xkmsService == nil {
		return nil, ErrSealStoreNotConfigured
	}
	resp, err := s.xkmsService.SealStoreStatus(ctx)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
