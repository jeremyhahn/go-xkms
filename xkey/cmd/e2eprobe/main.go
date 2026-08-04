// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Backend-connected E2E driver for xkey-android. Acts as the desktop initiator
// against the Android phone's TcpHsmServer over an adb-forwarded TCP socket:
// performs the pre-handshake identity exchange + Noise XX handshake, then
// exercises the live local.* surface (getInfo, listKeys, generateKey [software
// /exportable], symmetricEncrypt/Decrypt round-trip, syncStatus) with per-step
// pass/fail reporting. Validates real wire interop between go-xkms
// pkg/pairing and the Kotlin RequestHandler/StreamPairingSession.
//
// Usage: go run ./cmd/e2eprobe [host:port]   (default localhost:8444)
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

type noopHandler struct{}

func (noopHandler) HandleRequest(ctx context.Context, req *pairing.Request) *pairing.Response {
	return nil
}

// step records the outcome of a single probe operation.
type step struct {
	name     string
	required bool
	ok       bool
	detail   string
}

func main() {
	addr := "localhost:8444"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	staticKey, err := pairing.GenerateStaticKey()
	fatalIf(err, "generate static key")

	tr, err := pairing.NewTCPTransport(&pairing.TCPTransportConfig{
		Address: addr, ConnectTimeout: 10 * time.Second, OperationTimeout: 30 * time.Second,
	})
	fatalIf(err, "create transport")
	fatalIf(tr.Connect(ctx), "tcp connect to "+addr)
	defer func() { _ = tr.Close() }()
	fmt.Println("OK   tcp connected:", addr)

	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{LocalStaticKey: staticKey, IsInitiator: true})
	fatalIf(err, "create noise session")
	fatalIf(pairing.PerformHandshake(ctx, &pairing.HandshakeConfig{
		Transport: tr, Session: session, Logger: logger, LocalStaticPublicKey: staticKey.Public,
	}), "noise handshake")
	fmt.Println("OK   noise handshake (identity exchange + XX)")

	router := pairing.NewMessageRouter(tr, session, noopHandler{}, logger)
	router.Start()
	defer router.Stop()

	call := func(method string, params interface{}) (map[string]json.RawMessage, error) {
		resp, err := router.SendRequest(ctx, pairing.NewRequest(method, params))
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, &MessageError{Msg: fmt.Sprintf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)}
		}
		out := map[string]json.RawMessage{}
		_ = json.Unmarshal(resp.Result, &out)
		return out, nil
	}

	var steps []step
	record := func(name string, required bool, err error, detail string) {
		steps = append(steps, step{name, required, err == nil, detail + errSuffix(err)})
	}

	// 1) getInfo
	_, err = call("getInfo", nil)
	record("getInfo", true, err, "")

	// 2) local.listKeys (informational)
	_, err = call("local.listKeys", map[string]interface{}{})
	record("local.listKeys", false, err, "")

	// 3) local.generateKey — exportable software-backed AES-256 symmetric key
	keyID := "e2e-sw-key"
	_, err = call("local.generateKey", map[string]interface{}{
		"keyId": keyID, "keyType": "encryption", "algorithm": "AES-256",
		"exportable": true, "requireUserVerification": false, "label": "e2e probe key",
	})
	record("local.generateKey (exportable AES-256)", true, err, "")

	// 4) symmetricEncrypt + symmetricDecrypt round-trip on that key
	plaintext := []byte("xkey-e2e-roundtrip")
	var ctB64 string
	if err == nil {
		var enc map[string]json.RawMessage
		enc, err = call("local.symmetricEncrypt", map[string]interface{}{
			"keyId": keyID, "data": base64.StdEncoding.EncodeToString(plaintext),
		})
		if err == nil {
			_ = json.Unmarshal(enc["data"], &ctB64)
		}
		record("local.symmetricEncrypt", true, err, "")

		if err == nil {
			var dec map[string]json.RawMessage
			dec, derr := call("local.symmetricDecrypt", map[string]interface{}{"keyId": keyID, "data": ctB64})
			if derr == nil {
				var ptB64 string
				_ = json.Unmarshal(dec["data"], &ptB64)
				got, _ := base64.StdEncoding.DecodeString(ptB64)
				if string(got) != string(plaintext) {
					derr = &MessageError{Msg: fmt.Sprintf("round-trip mismatch: got %q", string(got))}
				}
			}
			record("local.symmetricDecrypt (round-trip)", true, derr, "")
		}
	}

	// 5) local.syncStatus (informational)
	if st, serr := call("local.syncStatus", map[string]interface{}{}); serr == nil {
		record("local.syncStatus", false, nil, fmt.Sprintf("device_id=%s", trimRaw(st["device_id"])))
	} else {
		record("local.syncStatus", false, serr, "")
	}

	// 6) cleanup
	_, _ = call("local.deleteKey", map[string]interface{}{"keyId": keyID})

	// Report
	fmt.Println("\n=== E2E results ===")
	failed := 0
	for _, s := range steps {
		mark := "PASS"
		if !s.ok {
			mark = "FAIL"
			if s.required {
				failed++
			} else {
				mark = "warn"
			}
		}
		req := ""
		if !s.required {
			req = " (optional)"
		}
		fmt.Printf("  [%s] %s%s %s\n", mark, s.name, req, s.detail)
	}
	if failed > 0 {
		fmt.Printf("\nE2E FAILED: %d required step(s) failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nE2E PASSED: all required steps succeeded")
}

func fatalIf(err error, what string) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return "-> " + err.Error()
}

func trimRaw(r json.RawMessage) string {
	s := string(r)
	if len(s) >= 2 && s[0] == '"' {
		s = s[1 : len(s)-1]
	}
	return s
}
