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

package client

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// stubTransportClient implements TransportClient with scripted responses.
type stubTransportClient struct {
	beginRegResp   *transport.BeginRegistrationResponse
	beginRegErr    error
	finishRegResp  *transport.FinishRegistrationResponse
	finishRegErr   error
	beginAuthResp  *transport.BeginAuthenticationResponse
	beginAuthErr   error
	finishAuthResp *transport.FinishAuthenticationResponse
	finishAuthErr  error
}

func (s *stubTransportClient) BeginRegistration(context.Context, *transport.BeginRegistrationRequest) (*transport.BeginRegistrationResponse, error) {
	return s.beginRegResp, s.beginRegErr
}

func (s *stubTransportClient) FinishRegistration(context.Context, *transport.FinishRegistrationRequest) (*transport.FinishRegistrationResponse, error) {
	return s.finishRegResp, s.finishRegErr
}

func (s *stubTransportClient) BeginAuthentication(context.Context, *transport.BeginAuthenticationRequest) (*transport.BeginAuthenticationResponse, error) {
	return s.beginAuthResp, s.beginAuthErr
}

func (s *stubTransportClient) FinishAuthentication(context.Context, *transport.FinishAuthenticationRequest) (*transport.FinishAuthenticationResponse, error) {
	return s.finishAuthResp, s.finishAuthErr
}

func TestNewTransportRelyingParty_NilClient(t *testing.T) {
	_, err := NewTransportRelyingParty(nil)
	if !errors.Is(err, ErrNilTransportClient) {
		t.Errorf("error = %v, want %v", err, ErrNilTransportClient)
	}
}

func TestTransportRelyingParty_FinishRegistration_Rejection(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{
		finishRegResp: &transport.FinishRegistrationResponse{Success: false, Message: "attestation rejected"},
	})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	_, err = rp.FinishRegistration(context.Background(), &BeginResult{SessionID: "s1"}, &RegistrationRequest{Username: "a@b.com"}, []byte("{}"))
	if !errors.Is(err, ErrRegistrationFailed) {
		t.Errorf("error = %v, want to wrap %v", err, ErrRegistrationFailed)
	}
	var rejection *RelyingPartyRejection
	if !errors.As(err, &rejection) {
		t.Fatalf("error = %v, want *RelyingPartyRejection", err)
	}
	if rejection.Message != "attestation rejected" {
		t.Errorf("Message = %q, want %q", rejection.Message, "attestation rejected")
	}
}

func TestTransportRelyingParty_FinishAuthentication_Rejection(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{
		finishAuthResp: &transport.FinishAuthenticationResponse{Success: false, Message: "assertion rejected"},
	})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	_, err = rp.FinishAuthentication(context.Background(), &BeginResult{SessionID: "s1"}, &AuthenticationRequest{Username: "a@b.com"}, []byte("{}"))
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("error = %v, want to wrap %v", err, ErrAuthenticationFailed)
	}
}

func TestTransportRelyingParty_BeginRegistration_TransportError(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{beginRegErr: errors.New("connection reset")})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	_, err = rp.BeginRegistration(context.Background(), &RegistrationRequest{Username: "a@b.com"})
	if !errors.Is(err, ErrServerUnavailable) {
		t.Errorf("error = %v, want to wrap %v", err, ErrServerUnavailable)
	}
}

func TestTransportRelyingParty_FinishRegistration_TransportError(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{finishRegErr: errors.New("connection reset")})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	_, err = rp.FinishRegistration(context.Background(), &BeginResult{SessionID: "s1"}, &RegistrationRequest{Username: "a@b.com"}, []byte("{}"))
	if !errors.Is(err, ErrRegistrationFailed) {
		t.Errorf("error = %v, want to wrap %v", err, ErrRegistrationFailed)
	}
}

func TestTransportRelyingParty_FinishRegistration_Success(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{
		finishRegResp: &transport.FinishRegistrationResponse{Success: true, CredentialID: "cred-1", Token: "jwt"},
	})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	result, err := rp.FinishRegistration(context.Background(), &BeginResult{SessionID: "s1"}, &RegistrationRequest{Username: "a@b.com"}, []byte("{}"))
	if err != nil {
		t.Fatalf("FinishRegistration() error: %v", err)
	}
	if result.CredentialID != "cred-1" || result.JWT != "jwt" {
		t.Errorf("result = %+v, want CredentialID=cred-1 JWT=jwt", result)
	}
}

func TestTransportRelyingParty_BeginAuthentication_TransportError(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{beginAuthErr: errors.New("connection reset")})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	_, err = rp.BeginAuthentication(context.Background(), &AuthenticationRequest{Username: "a@b.com"})
	if !errors.Is(err, ErrServerUnavailable) {
		t.Errorf("error = %v, want to wrap %v", err, ErrServerUnavailable)
	}
}

func TestTransportRelyingParty_FinishAuthentication_TransportError(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{finishAuthErr: errors.New("connection reset")})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	_, err = rp.FinishAuthentication(context.Background(), &BeginResult{SessionID: "s1"}, &AuthenticationRequest{Username: "a@b.com"}, []byte("{}"))
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("error = %v, want to wrap %v", err, ErrAuthenticationFailed)
	}
}

func TestTransportRelyingParty_FinishAuthentication_Success(t *testing.T) {
	rp, err := NewTransportRelyingParty(&stubTransportClient{
		finishAuthResp: &transport.FinishAuthenticationResponse{Success: true, Token: "jwt", Username: "a@b.com"},
	})
	if err != nil {
		t.Fatalf("NewTransportRelyingParty() error: %v", err)
	}

	result, err := rp.FinishAuthentication(context.Background(), &BeginResult{SessionID: "s1"}, &AuthenticationRequest{Username: "a@b.com"}, []byte("{}"))
	if err != nil {
		t.Fatalf("FinishAuthentication() error: %v", err)
	}
	if result.JWT != "jwt" || result.UserID != "a@b.com" {
		t.Errorf("result = %+v, want JWT=jwt UserID=a@b.com", result)
	}
}
