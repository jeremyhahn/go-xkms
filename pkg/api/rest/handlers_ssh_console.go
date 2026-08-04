// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"errors"
	"net/http"
	"strconv"

	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// resolveConsoleTarget authorizes an SSH console WebSocket request (the
// AuthenticationMiddleware has already gated it) and maps it to a console
// target. Connection parameters arrive as query string values:
//
//	/xkms/v1/ssh/console?key=<name>&scope=<scope>&owner=<owner>
//	    &host=<host>&port=<port>&user=<user>
//
// The signer is resolved through the server's SSH client (so hardware-backed
// keys never export private material); host verification uses the server's pin
// store.
func (s *Server) resolveConsoleTarget(r *http.Request) (*sdkssh.ConsoleTarget, error) {
	q := r.URL.Query()
	host := q.Get("host")
	keyName := q.Get("key")
	if host == "" {
		return nil, errors.New("ssh console: host is required")
	}
	if keyName == "" {
		return nil, errors.New("ssh console: key is required")
	}

	scope := q.Get("scope")
	if scope == "" {
		scope = "user"
	}
	owner := q.Get("owner")
	if owner == "" {
		owner = "default"
	}

	port := 0
	if p := q.Get("port"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}

	signer, err := s.sshClient.Keys().Signer(r.Context(), sdkssh.GetKeyRequest{
		Scope: scope, Owner: owner, Name: keyName,
	})
	if err != nil {
		return nil, err
	}

	return &sdkssh.ConsoleTarget{
		Host:     host,
		Port:     port,
		User:     q.Get("user"),
		Signer:   signer,
		HostKeys: s.sshHostKeys,
		Scope:    scope,
		Owner:    owner,
	}, nil
}
