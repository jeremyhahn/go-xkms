package client

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
)

func TestZZProbeLive(t *testing.T) {
	if os.Getenv("PROBE_URL") == "" {
		t.Skip()
	}
	c, err := NewClient(&Config{
		ServerURL:            os.Getenv("PROBE_URL"),
		TLSConfig:            &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		AuthenticatorAdapter: NewSoftwareAdapter(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Register(context.Background(), &RegistrationRequest{Username: "probe@example.com", DisplayName: "P"})
	t.Logf("register err: %v", err)
}
