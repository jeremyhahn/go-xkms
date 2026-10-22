// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Backend-connected E2E conformance probe for xkey-android. Acts as the
// desktop initiator against the Android phone's TcpHsmServer over an
// adb-forwarded TCP socket: performs the pre-handshake identity exchange +
// Noise XX handshake and pairing.confirm, then sweeps the phone's protocol
// surface family by family with cryptographic verification on the Go side
// (ECDSA signature verify, ECDH agreement cross-check, TOTP cross-compute,
// certificate and backup round-trips). Validates real wire interop between
// go-xkms pkg/pairing and the Kotlin RequestHandler/StreamPairingSession.
//
// Usage: go run ./cmd/e2eprobe [host:port]   (default localhost:8444)
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

type noopHandler struct{}

func (noopHandler) HandleRequest(ctx context.Context, req *pairingproto.Request) *pairingproto.Response {
	return nil
}

// step records the outcome of a single probe operation.
type step struct {
	name     string
	required bool
	ok       bool
	detail   string
}

type prober struct {
	call  func(method string, params interface{}) (map[string]json.RawMessage, error)
	steps []step
}

func (p *prober) record(name string, required bool, err error, detail string) {
	p.steps = append(p.steps, step{name, required, err == nil, detail + errSuffix(err)})
}

// requiredCall runs a call and records it as a required step, returning the
// result (nil on error).
func (p *prober) requiredCall(name, method string, params interface{}) map[string]json.RawMessage {
	out, err := p.call(method, params)
	p.record(name, true, err, "")
	if err != nil {
		return nil
	}
	return out
}

// probeShutdownTimeout bounds the wait for the message router's receive loop.
// It parks in an uncancellable Receive and only observes shutdown between
// messages, so this cannot be an unbounded join; see go-xkms#30.
const probeShutdownTimeout = 5 * time.Second

// probeExit carries a non-zero status out of the teardown defer. Registered
// first below so it runs LAST, after teardown has had its say.
var probeExit int

func main() {
	// Before anything constructs protected memory: a debugger or a same-user
	// process must not be able to read the static key through ptrace or
	// /proc/<pid>/mem.
	_, err := secure.HardenProcess(nil)
	fatalIf(err, "process hardening")

	// Registered before anything else, so it is the final defer to run and
	// can act on whatever teardown recorded.
	defer func() {
		if probeExit != 0 {
			os.Exit(probeExit)
		}
	}()

	addr := "localhost:8444"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// A fixed key can be supplied so the phone already knows this peer and
	// auto-confirms pairing. Approving a new peer is a human decision by
	// design, so an unattended run pre-establishes the trust relationship
	// instead of trying to automate the tap.
	//
	//   XKEY_PROBE_STATIC_KEY=<base64 32-byte private key>
	staticKey, err := probeStaticKey()
	fatalIf(err, "load static key")
	fmt.Println("OK   static public key:", base64.StdEncoding.EncodeToString(staticKey.PublicBytes()))

	tr, err := pairing.NewTCPTransport(&pairing.TCPTransportConfig{
		Address: addr, ConnectTimeout: 10 * time.Second, OperationTimeout: 30 * time.Second,
	})
	fatalIf(err, "create transport")
	fatalIf(tr.Connect(ctx), "tcp connect to "+addr)
	fmt.Println("OK   tcp connected:", addr)

	if !probe(ctx, tr, staticKey, logger, os.Stdout) {
		probeExit = 1
	}
}

// probe pairs with the phone over tr, runs the conformance families and
// reports them to out. It takes ownership of tr and staticKey, and reports
// whether every required step passed and teardown released the key.
func probe(ctx context.Context, tr pairingproto.Transport, staticKey *bootstrap.NoiseStaticKey,
	logger *slog.Logger, out io.Writer) (passed bool) {
	c := &console{w: out}
	// Teardown is one ordered block rather than three defers, because defer
	// LIFO gave Stop -> Close -> Destroy with no join in between: Stop does not
	// wait for the receive loop, so the probe could free the key's protected
	// pages while that loop was still decrypting through the session. The
	// order that is actually correct is signal, unblock, join, release.
	var router *pairing.MessageRouter
	defer func() {
		if router != nil {
			router.Stop()
		}
		if err := tr.Close(); err != nil {
			logger.Warn("failed to close transport during teardown", "error", err)
		}
		if router != nil && !router.Join(probeShutdownTimeout) {
			logger.Warn("message router did not exit within the shutdown window; " +
				"retaining the static key rather than freeing pages it may still read")
			// Surfaced, not just logged. A probe whose whole purpose is to
			// verify the pairing path must not pass over a shutdown it
			// could not confirm — that is the same fail-open the components
			// below it were fixed to stop reporting.
			c.printf("FAIL message router did not exit within the shutdown window; " +
				"the static key was retained\n")
			passed = false
			return
		}
		staticKey.Destroy()
	}()

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{LocalStaticKey: staticKey, IsInitiator: true})
	if err != nil {
		c.printf("FAIL create noise session: %v\n", err)
		return false
	}
	if err := pairingproto.PerformHandshake(ctx, &pairingproto.HandshakeConfig{
		Transport: tr, Session: session, Logger: logger, LocalStaticPublicKey: staticKey.PublicBytes(),
	}); err != nil {
		c.printf("FAIL noise handshake: %v\n", err)
		return false
	}
	c.printf("OK   noise handshake (identity exchange + XX)\n")

	router = pairing.NewMessageRouter(tr, session, noopHandler{}, logger)
	router.Start()

	p := &prober{}
	p.call = func(method string, params interface{}) (map[string]json.RawMessage, error) {
		resp, err := router.SendRequest(ctx, pairingproto.NewRequest(method, params))
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, &MessageError{Msg: fmt.Sprintf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)}
		}
		result := map[string]json.RawMessage{}
		if err := json.Unmarshal(resp.Result, &result); err != nil {
			// A malformed result must fail the step, not be silently
			// treated as an empty (all fields missing) response: this
			// probe exists to catch exactly this kind of wire deviation
			// from the phone.
			return nil, &MessageError{Msg: fmt.Sprintf("malformed rpc result for %s: %v", method, err)}
		}
		return result, nil
	}

	runID := fmt.Sprintf("%x", time.Now().UnixMilli())
	conformance(p, runID, staticKey.PublicBytes())
	return report(c, p.steps)
}

// conformance drives every method family against the paired phone, in the
// order a real xkey session reaches them, recording one step per check.
func conformance(p *prober, runID string, staticPublicKey []byte) {
	// --- Pairing ---
	p.requiredCall("pairing.confirm", "pairing.confirm", map[string]interface{}{
		"deviceName":   "e2eprobe",
		"publicKeyHex": hex.EncodeToString(staticPublicKey),
	})

	// --- Base methods ---
	p.requiredCall("ping", "ping", nil)

	var info pairingproto.GetInfoResult
	decodeResult(p, "getInfo", "getInfo", nil, &info)
	p.record("getInfo carries deviceName", true, requireNonEmpty("deviceName", info.DeviceName), "")
	p.record("getInfo carries supportedAlgorithms", true,
		requireNonZero("supportedAlgorithms", len(info.SupportedAlgorithms)), "")
	p.record("getInfo carries maxCredentials", true,
		requireNonZero("maxCredentials", info.MaxCredentials), "")

	var caps pairingproto.LocalGetCapabilitiesResult
	decodeResult(p, "local.getCapabilities", "local.getCapabilities", map[string]interface{}{}, &caps)
	p.record("getCapabilities carries deviceName", true, requireNonEmpty("deviceName", caps.DeviceName), "")
	p.record("getCapabilities carries supportedAlgorithms", true,
		requireNonZero("supportedAlgorithms", len(caps.SupportedAlgorithms)), "")
	p.record("getCapabilities carries supportedFormats", true,
		requireNonZero("supportedFormats", len(caps.SupportedFormats)), "")
	p.record("getCapabilities carries maxKeys", true, requireNonZero("maxKeys", caps.MaxKeys), "")

	// --- Asymmetric key lifecycle with Go-side signature verification ---
	ecKeyID := "e2e-ec-" + runID
	genRes := p.requiredCall("local.generateKey (ES256)", "local.generateKey", map[string]interface{}{
		"keyId": ecKeyID, "keyType": "signing", "algorithm": "ES256",
		"requireUserVerification": false, "preferStrongBox": false,
	})
	var phoneECPub *ecdsa.PublicKey
	if genRes != nil {
		if der := decodeB64(genRes["publicKeyDer"]); der != nil {
			if pub, perr := x509.ParsePKIXPublicKey(der); perr == nil {
				phoneECPub, _ = pub.(*ecdsa.PublicKey)
			}
		}
		if phoneECPub == nil {
			p.record("parse publicKeyDer", true, &MessageError{Msg: "missing/invalid publicKeyDer"}, "")
		}
	}

	payload := []byte("e2eprobe signature payload")
	if signRes := p.requiredCall("local.sign", "local.sign", map[string]interface{}{
		"keyId": ecKeyID, "data": base64.StdEncoding.EncodeToString(payload),
	}); signRes != nil && phoneECPub != nil {
		sig := decodeB64(signRes["signature"])
		digest := sha256.Sum256(payload)
		var verr error
		if !ecdsa.VerifyASN1(phoneECPub, digest[:], sig) {
			verr = &MessageError{Msg: "ECDSA signature does not verify against phone public key"}
		}
		p.record("verify phone ECDSA signature (Go side)", true, verr, "")
	}

	p.requiredCall("local.getPublicKey", "local.getPublicKey", map[string]interface{}{
		"keyId": ecKeyID, "format": "der",
	})
	p.requiredCall("local.listKeys", "local.listKeys", map[string]interface{}{})
	p.requiredCall("local.getKeyInfo", "local.getKeyInfo", map[string]interface{}{"keyId": ecKeyID})

	// --- ECDH cross-check ---
	if phoneECPub != nil {
		goPriv, gerr := ecdh.P256().GenerateKey(rand.Reader)
		if gerr == nil {
			goPubDER, _ := x509.MarshalPKIXPublicKey(goPriv.PublicKey())
			if ecdhRes, eerr := p.call("local.ecdh", map[string]interface{}{
				"keyId": ecKeyID, "peerPublicKey": base64.StdEncoding.EncodeToString(goPubDER),
			}); eerr != nil {
				p.record("local.ecdh", true, eerr, "")
			} else {
				phoneSecret := decodeB64(ecdhRes["sharedSecret"])
				phonePubECDH, perr := phoneECPub.ECDH()
				var xerr error
				if perr != nil {
					xerr = perr
				} else {
					goSecret, derr := goPriv.ECDH(phonePubECDH)
					if derr != nil {
						xerr = derr
					} else if !hmac.Equal(goSecret, phoneSecret) {
						xerr = &MessageError{Msg: "ECDH shared secrets differ"}
					}
				}
				p.record("local.ecdh (shared secret cross-check)", true, xerr, "")
			}
		}
	}

	// --- Symmetric: hardware + software exportable round-trips, HMAC ---
	symRoundtrip(p, "hw", "e2e-aes-hw-"+runID, false)
	symRoundtrip(p, "sw exportable", "e2e-aes-sw-"+runID, true)

	hmacKeyID := "e2e-hmac-" + runID
	if p.requiredCall("local.generateKey (HMAC-SHA256)", "local.generateKey", map[string]interface{}{
		"keyId": hmacKeyID, "keyType": "hmac", "algorithm": "HMAC-SHA256",
		"requireUserVerification": false, "preferStrongBox": false,
	}) != nil {
		if macRes := p.requiredCall("local.hmac", "local.hmac", map[string]interface{}{
			"keyId": hmacKeyID, "data": base64.StdEncoding.EncodeToString([]byte("mac me")),
		}); macRes != nil {
			var lerr error
			if len(decodeB64(macRes["mac"])) != 32 {
				lerr = &MessageError{Msg: "HMAC-SHA256 mac is not 32 bytes"}
			}
			p.record("local.hmac (length check)", true, lerr, "")
		}
		_, _ = p.call("local.deleteKey", map[string]interface{}{"keyId": hmacKeyID})
	}

	// --- PIN family ---
	pinFamily(p)

	// --- Exactly what the xkmsd phone backend sends ---
	// pkg/backend/phone/backend.go populates only keyId + algorithm: no
	// keyType, and symmetric algorithms spelled "AES256-GCM". Sending the
	// richer shape the rest of this probe uses would hide a break that only
	// the real backend hits.
	backendKeyID := "e2e-backend-" + runID
	p.requiredCall("local.generateKey (as xkmsd backend: no keyType)", "local.generateKey",
		map[string]interface{}{"keyId": backendKeyID, "algorithm": "ES256"})
	_, _ = p.call("local.deleteKey", map[string]interface{}{"keyId": backendKeyID})

	symBackendKeyID := "e2e-backend-sym-" + runID
	p.requiredCall("local.generateKey (as xkmsd backend: AES256-GCM)", "local.generateKey",
		map[string]interface{}{"keyId": symBackendKeyID, "algorithm": "AES256-GCM", "exportable": true})
	_, _ = p.call("local.deleteKey", map[string]interface{}{"keyId": symBackendKeyID})

	// --- PIV family with Go-side verification and cert round-trip ---
	pivFamily(p, runID)

	// --- OATH family with Go-side TOTP cross-compute ---
	oathFamily(p, runID)

	// --- Sync family ---
	p.requiredCall("local.syncStatus", "local.syncStatus", map[string]interface{}{})
	p.requiredCall("local.syncTrustStore", "local.syncTrustStore", map[string]interface{}{
		"certificates": []interface{}{},
	})
	p.requiredCall("local.syncOATH", "local.syncOATH", map[string]interface{}{
		"credentials": []interface{}{},
	})
	p.requiredCall("local.syncPasswords", "local.syncPasswords", map[string]interface{}{
		"passwords": []interface{}{},
	})

	// --- Backup round-trip ---
	backupFamily(p)

	// --- Key sharing ---
	sharingFamily(p, runID, ecKeyID)

	// --- Attestation (informational on emulators) ---
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	_, aerr := p.call("local.attestKey", map[string]interface{}{
		"keyId": ecKeyID, "nonce": base64.StdEncoding.EncodeToString(nonce),
	})
	p.record("local.attestKey", false, aerr, "")
	_, aerr = p.call("local.attestDevice", map[string]interface{}{
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	})
	p.record("local.attestDevice", false, aerr, "")

	// --- Device enrollment, this phone as an enrollee ---
	enrollmentFamily(p)
	tpmRefusalFamily(p)

	// --- FIDO2 listing ---
	p.requiredCall("local.listFido2Credentials", "local.listFido2Credentials", map[string]interface{}{
		"rpId": "e2eprobe.example.com",
	})

	// --- Error handling ---
	if _, uerr := p.call("local.definitelyNotAMethod", map[string]interface{}{}); uerr == nil {
		p.record("unknown method returns error", true, &MessageError{Msg: "expected an error response"}, "")
	} else {
		p.record("unknown method returns error", true, nil, "")
	}

	// --- Cleanup ---
	_, _ = p.call("local.deleteKey", map[string]interface{}{"keyId": ecKeyID})
}

// decodeResult decodes a method's result into the real pairing struct, not
// an ad-hoc map. A probe that hand-writes the JSON it expects proves only that
// the probe and the phone agree with each other: it cannot catch a field the
// Go contract renamed.
func decodeResult(p *prober, name, method string, params, target interface{}) {
	result, err := p.call(method, params)
	if err == nil {
		var encoded []byte
		if encoded, err = json.Marshal(result); err == nil {
			err = json.Unmarshal(encoded, target)
		}
	}
	p.record(name, true, err, "")
}

// symRoundtrip generates an AES-256 key (hardware or software/exportable) and
// verifies an encrypt/decrypt round-trip.
func symRoundtrip(p *prober, label, keyID string, exportable bool) {
	if p.requiredCall(fmt.Sprintf("local.generateKey (AES-256 %s)", label), "local.generateKey", map[string]interface{}{
		"keyId": keyID, "keyType": "secret", "algorithm": "AES-256",
		"exportable": exportable, "requireUserVerification": false, "preferStrongBox": false,
	}) == nil {
		return
	}
	plaintext := []byte("xkey-e2e-roundtrip-" + label)
	enc, err := p.call("local.symmetricEncrypt", map[string]interface{}{
		"keyId": keyID, "data": base64.StdEncoding.EncodeToString(plaintext),
	})
	p.record(fmt.Sprintf("local.symmetricEncrypt (%s)", label), true, err, "")
	if err == nil {
		var ctB64 string
		var derr error
		if uerr := json.Unmarshal(enc["data"], &ctB64); uerr != nil {
			derr = &MessageError{Msg: fmt.Sprintf("malformed symmetricEncrypt response: %v", uerr)}
		} else {
			var dec map[string]json.RawMessage
			dec, derr = p.call("local.symmetricDecrypt", map[string]interface{}{"keyId": keyID, "data": ctB64})
			if derr == nil {
				got := decodeB64(dec["data"])
				if !bytes.Equal(got, plaintext) {
					derr = &MessageError{Msg: fmt.Sprintf("round-trip mismatch: got %q", string(got))}
				}
			}
		}
		p.record(fmt.Sprintf("local.symmetricDecrypt round-trip (%s)", label), true, derr, "")
	}
	_, _ = p.call("local.deleteKey", map[string]interface{}{"keyId": keyID})
}

// pinFamily exercises SO/User PIN set, verify, change, and lockout reset.
func pinFamily(p *prober) {
	status, err := p.call("local.pinStatus", map[string]interface{}{})
	p.record("local.pinStatus", true, err, "")
	if err != nil {
		return
	}
	soPin, userPin, newUserPin := "87654321", "123456", "654321"
	soSet := string(status["soPinSet"]) == "true"
	if !soSet {
		_, serr := p.call("local.pinSet", map[string]interface{}{"pinType": "SO_PIN", "newPin": soPin})
		p.record("local.pinSet (SO_PIN)", true, serr, "")
		if serr != nil {
			return
		}
	}
	if _, uerr := p.call("local.pinSet", map[string]interface{}{
		"pinType": "USER_PIN", "soPin": soPin, "newPin": userPin,
	}); uerr != nil {
		// A pre-existing SO PIN from earlier runs means we can't drive the rest.
		p.record("local.pinSet (USER_PIN)", false, uerr, "(SO PIN from a previous run?)")
		return
	}
	p.record("local.pinSet (USER_PIN)", true, nil, "")

	_, verr := p.call("local.pinVerify", map[string]interface{}{"pin": userPin, "pinType": "USER_PIN"})
	p.record("local.pinVerify (USER_PIN)", true, verr, "")

	_, cerr := p.call("local.pinChange", map[string]interface{}{
		"pinType": "USER_PIN", "currentPin": userPin, "newPin": newUserPin,
	})
	p.record("local.pinChange (USER_PIN)", true, cerr, "")

	if _, werr := p.call("local.pinVerify", map[string]interface{}{"pin": "000000", "pinType": "USER_PIN"}); werr == nil {
		p.record("local.pinVerify rejects wrong PIN", true, &MessageError{Msg: "wrong PIN accepted"}, "")
	} else {
		p.record("local.pinVerify rejects wrong PIN", true, nil, "")
	}

	_, rerr := p.call("local.pinResetLockout", map[string]interface{}{"soPin": soPin})
	p.record("local.pinResetLockout", true, rerr, "")
}

// pivFamily generates a PIV key in slot 9a, verifies its signature in Go, and
// round-trips a Go-created self-signed certificate through the slot.
func pivFamily(p *prober, runID string) {
	// Go's field names and algorithm spelling, per protocol_piv.go.
	gen := p.requiredCall("local.pivGenerateKey (Go names: slot/ECDSA-P256)", "local.pivGenerateKey",
		map[string]interface{}{"slot": "9a", "algorithm": "ECDSA-P256"})
	if gen == nil {
		return
	}
	var pivPub *ecdsa.PublicKey
	if der := decodeB64(gen["public_key_der"]); der != nil {
		if pub, perr := x509.ParsePKIXPublicKey(der); perr == nil {
			pivPub, _ = pub.(*ecdsa.PublicKey)
		}
	}

	p.requiredCall("local.pivListSlots", "local.pivListSlots", map[string]interface{}{})

	payload := []byte("piv payload")
	if signRes := p.requiredCall("local.pivSign", "local.pivSign", map[string]interface{}{
		"slot": "9a", "data": base64.StdEncoding.EncodeToString(payload), "algorithm": "ECDSA-P256",
	}); signRes != nil && pivPub != nil {
		digest := sha256.Sum256(payload)
		var verr error
		if !ecdsa.VerifyASN1(pivPub, digest[:], decodeB64(signRes["signature"])) {
			verr = &MessageError{Msg: "PIV signature does not verify"}
		}
		p.record("verify PIV signature (Go side)", true, verr, "")
	}

	// Certificate round-trip with a Go-generated self-signed certificate.
	certDER, cerr := selfSignedCert("e2eprobe-piv-" + runID)
	if cerr != nil {
		p.record("generate test certificate", true, cerr, "")
		return
	}
	_, ierr := p.call("local.pivImportCert", map[string]interface{}{
		"slot": "9a", "certificate_der": base64.StdEncoding.EncodeToString(certDER),
	})
	p.record("local.pivImportCert", true, ierr, "")
	if ierr == nil {
		got, gerr := p.call("local.pivGetCert", map[string]interface{}{"slot": "9a"})
		if gerr == nil && !bytes.Equal(decodeB64(got["certificate_der"]), certDER) {
			gerr = &MessageError{Msg: "certificate round-trip mismatch"}
		}
		p.record("local.pivGetCert (round-trip)", true, gerr, "")
	}
}

// oathFamily adds a TOTP credential, cross-computes the expected code in Go,
// and removes the credential.
func oathFamily(p *prober, runID string) {
	// 20 bytes, the RFC 4226 recommended length. The 16-character
	// "JBSWY3DPEHPK3PXP" of every worked example decodes to 10 bytes, and
	// crypto/hmac under GODEBUG=fips140=only refuses keys below 112 bits by
	// panicking -- so the FIPS arm of this probe would have killed the process
	// on a secret length, after the algorithm gate had already been satisfied.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	name := "e2e-oath-" + runID
	algorithm, digest := oathProbeAlgorithm()
	added := p.requiredCall("local.oathAdd", "local.oathAdd", map[string]interface{}{
		"credential": map[string]interface{}{
			"name": name, "issuer": "e2eprobe", "account_name": "probe@example.com",
			"secret": secret, "type": "totp", "algorithm": algorithm, "digits": 6, "period": 30,
		},
	})
	if added == nil {
		return
	}

	list := p.requiredCall("local.oathList", "local.oathList", map[string]interface{}{})
	credentialID := ""
	if list != nil {
		var creds []map[string]interface{}
		if uerr := json.Unmarshal(list["credentials"], &creds); uerr != nil {
			p.record("find added OATH credential", true,
				&MessageError{Msg: fmt.Sprintf("malformed oathList response: %v", uerr)}, "")
			return
		}
		for _, c := range creds {
			if c["issuer"] == "e2eprobe" {
				credentialID, _ = c["name"].(string)
			}
		}
	}
	if credentialID == "" {
		p.record("find added OATH credential", true, &MessageError{Msg: "credential not in listing"}, "")
		return
	}

	if genRes := p.requiredCall("local.oathGenerate", "local.oathGenerate", map[string]interface{}{
		"credential_id": credentialID,
	}); genRes != nil {
		var code string
		var terr error
		if uerr := json.Unmarshal(genRes["code"], &code); uerr != nil {
			terr = &MessageError{Msg: fmt.Sprintf("malformed oathGenerate response: %v", uerr)}
		} else {
			now := time.Now().Unix() / 30
			if code != totp(secret, now, digest) &&
				code != totp(secret, now-1, digest) &&
				code != totp(secret, now+1, digest) {
				terr = &MessageError{Msg: fmt.Sprintf("TOTP mismatch (%s): phone=%s go=%s",
					algorithm, code, totp(secret, now, digest))}
			}
		}
		p.record("TOTP cross-compute (Go side)", true, terr, "")
	}

	_, rerr := p.call("local.oathRemove", map[string]interface{}{"credential_id": credentialID})
	p.record("local.oathRemove", true, rerr, "")
}

// backupFamily round-trips an opaque blob through the phone's backup store.
func backupFamily(p *prober) {
	blob := make([]byte, 256)
	_, _ = rand.Read(blob)
	created, err := p.call("local.createBackup", map[string]interface{}{
		"backup_data": base64.StdEncoding.EncodeToString(blob), "label": "e2eprobe",
	})
	p.record("local.createBackup", true, err, "")
	if err != nil {
		return
	}
	var backupID string
	var rerr error
	if uerr := json.Unmarshal(created["backup_id"], &backupID); uerr != nil {
		rerr = &MessageError{Msg: fmt.Sprintf("malformed createBackup response: %v", uerr)}
	} else {
		var restored map[string]json.RawMessage
		restored, rerr = p.call("local.restoreBackup", map[string]interface{}{"backup_id": backupID})
		if rerr == nil && !bytes.Equal(decodeB64(restored["backup_data"]), blob) {
			rerr = &MessageError{Msg: "backup round-trip mismatch"}
		}
	}
	p.record("local.restoreBackup (round-trip)", true, rerr, "")
}

// sharingFamily shares a Go public key and symmetric key to the phone, then
// exports them back per the sharing policy.
func sharingFamily(p *prober, runID, hwKeyID string) {
	// Public key share.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	_, err := p.call("local.sharePublicKey", map[string]interface{}{
		"public_key_pem": pemStr, "key_id": "e2e-share-" + runID, "label": "e2eprobe shared", "algorithm": "ES256",
	})
	p.record("local.sharePublicKey", true, err, "")

	// Symmetric share + export round-trip.
	material := make([]byte, 32)
	_, _ = rand.Read(material)
	label := "e2e-shared-sym-" + runID
	_, serr := p.call("local.shareSymmetric", map[string]interface{}{
		"wrapped_key": base64.StdEncoding.EncodeToString(material), "label": label,
		"algorithm": "AES", "key_size": 256,
	})
	p.record("local.shareSymmetric", true, serr, "")
	if serr == nil {
		// A key a peer pushed to us is accepted for local use, but the peer
		// does not thereby earn the right to pull it back: inbound material is
		// stored non-exportable until the user grants a sharing policy.
		_, eerr := p.call("local.importSharedKey", map[string]interface{}{"key_id": label})
		var verdict error
		if eerr == nil {
			verdict = &MessageError{Msg: "re-export of an inbound shared key must be refused"}
		}
		p.record("local.importSharedKey refuses an inbound shared key", true, verdict, "")
	}

	// Hardware key must export public-only. It has to be marked shareable
	// first, otherwise the policy gate refuses before the backing check runs —
	// the point here is the BACKING boundary, not the policy.
	shareableHwKeyID := "e2e-hw-shareable-" + runID
	if p.requiredCall("local.generateKey (shareable hardware key)", "local.generateKey",
		map[string]interface{}{
			"keyId": shareableHwKeyID, "keyType": "signing", "algorithm": "ES256",
			"shareable": true, "requireUserVerification": false, "preferStrongBox": false,
		}) == nil {
		return
	}
	defer func() { _, _ = p.call("local.deleteKey", map[string]interface{}{"keyId": shareableHwKeyID}) }()

	exported, herr := p.call("local.importSharedKey", map[string]interface{}{"key_id": shareableHwKeyID})
	if herr == nil {
		var exportable bool
		// A malformed exportable field must not be read as "false" here:
		// that is the passing value, so silently defaulting to it on a
		// parse failure would let a genuinely non-conformant response
		// through the one check this step exists to make.
		if uerr := json.Unmarshal(exported["exportable"], &exportable); uerr != nil {
			herr = &MessageError{Msg: fmt.Sprintf("malformed importSharedKey response: %v", uerr)}
		} else if exportable {
			herr = &MessageError{Msg: "hardware key reported exportable"}
		} else if _, hasWrapped := exported["wrapped_key"]; hasWrapped {
			herr = &MessageError{Msg: "hardware key leaked wrapped_key"}
		}
	}
	p.record("local.importSharedKey (hardware public-only)", true, herr, "")
}

// selfSignedCert creates a minimal self-signed ECDSA certificate and returns
// its DER encoding.
func selfSignedCert(cn string) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	return x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
}

// totp computes an RFC 6238 TOTP (SHA1, 6 digits) for the given Base32 secret.
//
// CALLERS MUST CHECK fipsMode() FIRST. crypto/hmac rejects SHA-1 under
// GODEBUG=fips140=only by panicking, so this cannot be made to return an error
// from inside; the guard has to be at the call site. See the one caller.
// and time counter.
// fipsMode reports whether this process is under FIPS 140 rules, by asking
// the Go standard library directly (go-xkms #21): GODEBUG=fips140=on|only at
// runtime, or a GOFIPS140 build, both surface through crypto/fips140.Enabled.
// Indirected through a variable so a test can drive both sides of the branch
// below: the alternative is running the suite twice under different
// environments, which no CI job here does, and an ungated branch is one
// nobody ever executes.
var fipsMode = fips140.Enabled

// oathProbeAlgorithm picks the digest the probe enrolls and cross-computes.
//
// The probe used to enroll SHA-1 unconditionally, which RFC 6238 makes the
// TOTP default. Under FIPS that is not merely disallowed: crypto/hmac PANICS
// on SHA-1 with GODEBUG=fips140=only, so the Go-side cross-check would kill
// the probe, and oathGenerate now refuses the credential outright — a required
// step that can only fail. Enrolling SHA-256 instead keeps the cross-check
// REAL under FIPS rather than skipping it, and exercises the generate path
// that a FIPS deployment actually uses.
func oathProbeAlgorithm() (string, func() hash.Hash) {
	if fipsMode() {
		return "SHA256", sha256.New
	}
	return "SHA1", sha1.New
}

func totp(secretB32 string, counter int64, digest func() hash.Hash) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(digest, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// requireNonEmpty reports a field the phone left blank, which is how a renamed
// JSON key manifests once Go decodes into its own struct.
func requireNonEmpty(field, value string) error {
	if value == "" {
		return &MessageError{Msg: fmt.Sprintf("%s is empty; the phone likely emits a different JSON key", field)}
	}
	return nil
}

// requireNonZero is requireNonEmpty for counts and slice lengths.
func requireNonZero(field string, n int) error {
	if n == 0 {
		return &MessageError{Msg: fmt.Sprintf("%s is absent/zero; the phone likely emits a different JSON key", field)}
	}
	return nil
}

func decodeB64(raw json.RawMessage) []byte {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return out
}

// report writes every step's outcome to c and reports whether all required
// steps passed and the report was written.
func report(c *console, steps []step) bool {
	c.printf("\n=== E2E conformance results ===\n")
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
		c.printf("  [%s] %s%s %s\n", mark, s.name, req, s.detail)
	}
	if failed > 0 {
		c.printf("\nE2E FAILED: %d required step(s) failed\n", failed)
		return false
	}
	c.printf("\nE2E PASSED: all required steps succeeded\n")
	return c.err == nil
}

// console writes the probe's progress lines, latching the first write error
// so a report that could not be written fails the run instead of passing it.
type console struct {
	w   io.Writer
	err error
}

func (c *console) printf(format string, args ...interface{}) {
	if c.err == nil {
		_, c.err = fmt.Fprintf(c.w, format, args...)
	}
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
	return " -> " + err.Error()
}
