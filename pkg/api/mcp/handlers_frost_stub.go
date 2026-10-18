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

//go:build !frost

package mcp

import (
	"context"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// errFrostNotCompiled is the refusal every frost.* method answers when the
// binary is built without the frost tag. The methods stay registered in
// rpcMethods, so authorization runs first and the tool list matches a frost
// build.
var errFrostNotCompiled = &errs.Message{Msg: "FROST support not compiled - rebuild with '-tags frost'"}

// frostNotCompiled returns the refusal as a *KeyOpError. The code is
// ErrCodeMethodNotFound, matching pkg/api/grpc/service_frost_stub.go's
// errFrostNotCompiled (codes.Unimplemented) -- classToJSONRPCCode's mapping
// for apierrors.ClassUnimplemented is ErrCodeMethodNotFound, so this keeps
// the two transports' "not compiled in" refusal in the same class.
func frostNotCompiled() (interface{}, error) {
	return nil, &KeyOpError{Code: ErrCodeMethodNotFound, Err: errFrostNotCompiled}
}

func (s *Server) handleFrostGenerateKey(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostImportKey(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostListKeys(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostGetKey(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostDeleteKey(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostGenerateNonces(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostSignRound(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostAggregate(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}

func (s *Server) handleFrostVerify(context.Context, *JSONRPCRequest) (interface{}, error) {
	return frostNotCompiled()
}
