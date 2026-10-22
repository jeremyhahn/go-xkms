package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"
)

// conformantPhone is the fake phone with the base, key-lifecycle, sync,
// attestation and FIDO2 methods conformance reaches, on top of the families.
func conformantPhone(t *testing.T) *phone {
	t.Helper()
	ph := newPhone(t)
	ok := func(result map[string]interface{}) phoneHandler {
		return func(map[string]interface{}) (interface{}, error) { return result, nil }
	}
	ph.handlers["pairing.confirm"] = ok(map[string]interface{}{"confirmed": true})
	ph.handlers["ping"] = ok(map[string]interface{}{"pong": true})
	ph.handlers["getInfo"] = ok(map[string]interface{}{
		"version": "1", "deviceName": "pixel", "supportedAlgorithms": []int{-7}, "maxCredentials": 25,
	})
	ph.handlers["local.getCapabilities"] = ok(map[string]interface{}{
		"deviceName": "pixel", "supportedAlgorithms": []string{"ES256"},
		"supportedFormats": []string{"der"}, "maxKeys": 64,
	})
	ph.handlers["local.sign"] = ph.sign
	ph.handlers["local.ecdh"] = ph.ecdh
	ph.handlers["local.hmac"] = ph.hmac
	for _, method := range []string{
		"local.getPublicKey", "local.listKeys", "local.getKeyInfo",
		"local.syncStatus", "local.syncTrustStore", "local.syncOATH", "local.syncPasswords",
		"local.attestKey", "local.attestDevice", "local.listFido2Credentials",
	} {
		ph.handlers[method] = ok(map[string]interface{}{"ok": true})
	}
	return ph
}

func (ph *phone) sign(params map[string]interface{}) (interface{}, error) {
	key, found := ph.ecKeys[param(params, "keyId")]
	if !found {
		return nil, rpcError(-32004, "key not found")
	}
	data, err := paramBytes(params, "data")
	if err != nil {
		return nil, rpcError(-32602, "data is not base64")
	}
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	ph.must(err)
	return map[string]interface{}{"signature": b64(sig)}, nil
}

func (ph *phone) ecdh(params map[string]interface{}) (interface{}, error) {
	key, found := ph.ecKeys[param(params, "keyId")]
	if !found {
		return nil, rpcError(-32004, "key not found")
	}
	der, err := paramBytes(params, "peerPublicKey")
	if err != nil {
		return nil, rpcError(-32602, "peerPublicKey is not base64")
	}
	peer, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, rpcError(-32602, "peerPublicKey does not parse")
	}
	peerECDH, err := peer.(*ecdsa.PublicKey).ECDH()
	ph.must(err)
	priv, err := key.ECDH()
	ph.must(err)
	secret, err := priv.ECDH(peerECDH)
	ph.must(err)
	return map[string]interface{}{"sharedSecret": b64(secret)}, nil
}

func (ph *phone) hmac(params map[string]interface{}) (interface{}, error) {
	secret, found := ph.aesKeys[param(params, "keyId")]
	if !found {
		return nil, rpcError(-32004, "key not found")
	}
	data, err := paramBytes(params, "data")
	if err != nil {
		return nil, rpcError(-32602, "data is not base64")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return map[string]interface{}{"mac": b64(mac.Sum(nil))}, nil
}

func TestConformance_PassesAgainstAConformantPhone(t *testing.T) {
	ph := conformantPhone(t)
	p := ph.prober()

	conformance(p, "run", []byte{0x01, 0x02})

	if failed := failedSteps(p); len(failed) > 0 {
		t.Fatalf("steps failed against a conformant phone: %v", failed)
	}
	for _, name := range []string{
		"verify phone ECDSA signature (Go side)",
		"local.ecdh (shared secret cross-check)",
		"local.hmac (length check)",
		"unknown method returns error",
	} {
		stepNamed(t, p, name)
	}
	if len(ph.ecKeys) != 0 || len(ph.aesKeys) != 0 {
		t.Fatalf("probe keys left on the phone: %d EC, %d symmetric", len(ph.ecKeys), len(ph.aesKeys))
	}

	var out bytes.Buffer
	if !report(&console{w: &out}, p.steps) {
		t.Fatalf("report failed a conformant run:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "E2E PASSED") {
		t.Fatalf("report output = %q, want the pass line", out.String())
	}
}

func TestConformance_RecordsDeviantPhones(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	answer := func(result map[string]interface{}) phoneHandler {
		return func(map[string]interface{}) (interface{}, error) { return result, nil }
	}
	tests := []struct {
		name       string
		method     string
		handler    phoneHandler
		step       string
		wantDetail string
	}{
		{"getInfo without a device name", "getInfo",
			answer(map[string]interface{}{"supportedAlgorithms": []int{-7}, "maxCredentials": 1}),
			"getInfo carries deviceName", "deviceName"},
		{"getInfo with a renamed field type", "getInfo",
			answer(map[string]interface{}{"supportedAlgorithms": "ES256"}),
			"getInfo", "cannot unmarshal"},
		{"getCapabilities refused", "local.getCapabilities",
			func(map[string]interface{}) (interface{}, error) { return nil, rpcError(-32000, "busy") },
			"local.getCapabilities", "busy"},
		{"generateKey without a public key", "local.generateKey",
			answer(map[string]interface{}{"keyId": "k"}),
			"parse publicKeyDer", "missing/invalid publicKeyDer"},
		{"signature from another key", "local.sign", func(params map[string]interface{}) (interface{}, error) {
			digest := sha256.Sum256([]byte("e2eprobe signature payload"))
			sig, err := ecdsa.SignASN1(rand.Reader, otherKey, digest[:])
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{"signature": b64(sig)}, nil
		}, "verify phone ECDSA signature (Go side)", "does not verify"},
		{"ECDH secret differs", "local.ecdh",
			answer(map[string]interface{}{"sharedSecret": b64(make([]byte, 32))}),
			"local.ecdh (shared secret cross-check)", "shared secrets differ"},
		{"ECDH refused", "local.ecdh",
			func(map[string]interface{}) (interface{}, error) { return nil, rpcError(-32003, "denied") },
			"local.ecdh", "denied"},
		{"HMAC of the wrong length", "local.hmac",
			answer(map[string]interface{}{"mac": b64([]byte("short"))}),
			"local.hmac (length check)", "not 32 bytes"},
		{"unknown method accepted", "local.definitelyNotAMethod",
			answer(map[string]interface{}{}),
			"unknown method returns error", "expected an error response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := conformantPhone(t)
			original := ph.handlers[tt.method]
			if tt.method == "local.generateKey" {
				// Only the ES256 signing key loses its public key; the
				// families' keys still generate normally.
				ph.handlers[tt.method] = func(params map[string]interface{}) (interface{}, error) {
					if strings.HasPrefix(param(params, "keyId"), "e2e-ec-") {
						return tt.handler(params)
					}
					return original(params)
				}
			} else {
				ph.handlers[tt.method] = tt.handler
			}
			p := ph.prober()

			conformance(p, "run", []byte{0x01})

			requireFailedStep(t, p, tt.step, tt.wantDetail)
			var out bytes.Buffer
			if report(&console{w: &out}, p.steps) {
				t.Fatal("report passed a run with a failed required step")
			}
			if !strings.Contains(out.String(), "E2E FAILED") {
				t.Fatalf("report output = %q, want the failure line", out.String())
			}
		})
	}
}

func TestReport_OptionalFailureIsAWarning(t *testing.T) {
	steps := []step{
		{name: "required", ok: true, required: true},
		{name: "attest", ok: false, required: false, detail: "-> unsupported"},
	}
	var out bytes.Buffer

	if !report(&console{w: &out}, steps) {
		t.Fatalf("an optional failure failed the run:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "[warn] attest (optional) -> unsupported") {
		t.Fatalf("report output = %q, want the optional step as a warning", out.String())
	}
}

// brokenWriter fails every write, as a closed stdout does.
type brokenWriter struct{}

var errBrokenWriter = &MessageError{Msg: "write failed"}

func (brokenWriter) Write([]byte) (int, error) { return 0, errBrokenWriter }

func TestReport_FailsWhenTheReportCannotBeWritten(t *testing.T) {
	c := &console{w: brokenWriter{}}

	if report(c, []step{{name: "required", ok: true, required: true}}) {
		t.Fatal("report passed a run whose results were never written")
	}
	if c.err != errBrokenWriter {
		t.Fatalf("console error = %v, want the first write error", c.err)
	}
}
