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

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
)

func withFIPSMode(t *testing.T, on bool) {
	t.Helper()

	original := fipsMode
	t.Cleanup(func() { fipsMode = original })
	fipsMode = func() bool { return on }
}

// The probe enrolled SHA-1 unconditionally and cross-computed it in Go. Under
// FIPS both halves are broken: oathGenerate refuses the credential, so the
// required step could only ever fail, and the Go-side HMAC-SHA1 PANICS with
// GODEBUG=fips140=only. Selecting SHA-256 keeps the cross-check real instead of
// skipping it (raised in review on PR #76).
func TestOathProbeAlgorithm_UsesSHA256UnderFIPS(t *testing.T) {
	withFIPSMode(t, true)

	name, digest := oathProbeAlgorithm()
	if name != "SHA256" {
		t.Fatalf("algorithm = %q, want SHA256 under FIPS", name)
	}
	if got := digest().Size(); got != sha256.Size {
		t.Fatalf("digest size = %d, want %d: the name and the hash must agree, "+
			"or the probe cross-checks against a digest the phone did not use", got, sha256.Size)
	}
}

// Outside FIPS the probe must keep exercising SHA-1, which is the RFC 6238
// default and what every enrolled credential in the field actually uses.
// Silently probing only SHA-256 would stop testing the common path.
func TestOathProbeAlgorithm_UsesSHA1Otherwise(t *testing.T) {
	withFIPSMode(t, false)

	name, digest := oathProbeAlgorithm()
	if name != "SHA1" {
		t.Fatalf("algorithm = %q, want SHA1 outside FIPS", name)
	}
	if got := digest().Size(); got != sha1.Size {
		t.Fatalf("digest size = %d, want %d", got, sha1.Size)
	}
}

// totp now takes the digest as a parameter. A version that accepted it and
// went on using SHA-1 anyway would pass both tests above and still cross-check
// against the wrong hash, so pin the arithmetic to the RFC 6238 Appendix B
// vectors: T=59s with the default 30s step is counter 1.
//
// The RFC prints 8 digits; the probe compares 6, so these are the low six.
func TestTOTP_MatchesRFC6238Vectors(t *testing.T) {
	b32 := func(seed string) string {
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(seed))
	}

	tests := []struct {
		name   string
		seed   string
		digest func() hash.Hash
		want   string
	}{
		// Appendix B seeds are the ASCII digits repeated to the hash's key size.
		{"SHA1", "12345678901234567890", sha1.New, "287082"},
		{"SHA256", "12345678901234567890123456789012", sha256.New, "119246"},
		{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", sha512.New, "693936"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// RFC 6238 section 1.2 and Appendix B pin HMAC-SHA-1, which the
			// FIPS 140-3 module refuses, so that vector runs outside it.
			if tc.name == "SHA1" && !fipstest.OutsideFIPS(t) {
				return
			}
			if got := totp(b32(tc.seed), 1, tc.digest); got != tc.want {
				t.Fatalf("totp(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

// A secret the phone sent that cannot be decoded must not panic the probe.
func TestTOTP_UndecodableSecretReturnsEmpty(t *testing.T) {
	if got := totp("1811!!!!not-base32!!!!", 1, sha1.New); got != "" {
		t.Fatalf("totp = %q, want empty for an undecodable secret", got)
	}
}

// phoneHandler answers one RPC method. params is the request as the phone
// decodes it off the wire; the returned value is JSON-encoded as the result.
type phoneHandler func(params map[string]interface{}) (interface{}, error)

// phone is an in-memory stand-in for the xKey handset app the probe drives
// over Noise. Its handlers answer the way a conformant phone does, so every
// family passes against it; a test replaces one handler to model a phone that
// deviates, and checks that the probe records exactly that deviation.
type phone struct {
	t        *testing.T
	handlers map[string]phoneHandler
	calls    []string

	ecKeys    map[string]*ecdsa.PrivateKey
	aesKeys   map[string][]byte
	shareable map[string]bool
	inbound   map[string]bool
	soPin     string
	userPin   string
	pivKey    *ecdsa.PrivateKey
	pivCert   []byte
	oath      map[string]map[string]interface{}
	backups   map[string][]byte

	attestCA  *attesttest.CA
	deviceKey *ecdsa.PrivateKey

	// mutateEnrollment, when set, edits the enrollment package before it
	// is sent, to model a phone whose evidence is wrong in one way.
	mutateEnrollment func(res *pairingproto.LocalGetDeviceEnrollmentRequestResult)
}

func newPhone(t *testing.T) *phone {
	t.Helper()

	ph := &phone{
		t:         t,
		ecKeys:    map[string]*ecdsa.PrivateKey{},
		aesKeys:   map[string][]byte{},
		shareable: map[string]bool{},
		inbound:   map[string]bool{},
		oath:      map[string]map[string]interface{}{},
		backups:   map[string][]byte{},
		attestCA:  attesttest.NewCA(t, "phone attestation root"),
	}
	ph.handlers = map[string]phoneHandler{
		"local.generateKey":      ph.generateKey,
		"local.symmetricEncrypt": ph.symmetricEncrypt,
		"local.symmetricDecrypt": ph.symmetricDecrypt,
		"local.deleteKey":        ph.deleteKey,
		"local.pinStatus":        ph.pinStatus,
		"local.pinSet":           ph.pinSet,
		"local.pinVerify":        ph.pinVerify,
		"local.pinChange":        ph.pinChange,
		"local.pinResetLockout":  ph.pinResetLockout,
		"local.pivGenerateKey":   ph.pivGenerateKey,
		"local.pivListSlots":     ph.pivListSlots,
		"local.pivSign":          ph.pivSign,
		"local.pivImportCert":    ph.pivImportCert,
		"local.pivGetCert":       ph.pivGetCert,
		"local.oathAdd":          ph.oathAdd,
		"local.oathList":         ph.oathList,
		"local.oathGenerate":     ph.oathGenerate,
		"local.oathRemove":       ph.oathRemove,
		"local.createBackup":     ph.createBackup,
		"local.restoreBackup":    ph.restoreBackup,
		"local.sharePublicKey":   ph.sharePublicKey,
		"local.shareSymmetric":   ph.shareSymmetric,
		"local.importSharedKey":  ph.importSharedKey,

		pairingproto.MethodLocalGetDeviceEnrollmentRequest: ph.enrollmentRequest,
		pairingproto.MethodLocalStoreDeviceCredential:      ph.storeDeviceCredential,
	}
	for _, method := range []string{
		pairingproto.MethodLocalGetTCGCSRIDevID,
		pairingproto.MethodLocalActivateCredential,
		pairingproto.MethodLocalGetAttestationQuote,
		pairingproto.MethodLocalGetIAKPublicKey,
	} {
		ph.handlers[method] = notApplicable
	}
	return ph
}

// prober returns a prober whose RPCs this phone answers.
func (ph *phone) prober() *prober {
	return &prober{call: ph.call}
}

// call has the contract of the router-backed call main builds: an RPC error
// comes back as an error, a result as its decoded top-level fields.
func (ph *phone) call(method string, params interface{}) (map[string]json.RawMessage, error) {
	ph.t.Helper()
	ph.calls = append(ph.calls, method)

	handler, ok := ph.handlers[method]
	if !ok {
		return nil, rpcError(-32601, "method not found: "+method)
	}

	in := map[string]interface{}{}
	encodedParams, err := json.Marshal(params)
	ph.must(err)
	if params != nil {
		ph.must(json.Unmarshal(encodedParams, &in))
	}

	result, err := handler(in)
	if err != nil {
		return nil, err
	}
	encodedResult, err := json.Marshal(result)
	ph.must(err)
	out := map[string]json.RawMessage{}
	ph.must(json.Unmarshal(encodedResult, &out))
	return out, nil
}

func (ph *phone) called(method string) bool {
	for _, c := range ph.calls {
		if c == method {
			return true
		}
	}
	return false
}

func (ph *phone) must(err error) {
	ph.t.Helper()
	if err != nil {
		ph.t.Fatalf("phone: %v", err)
	}
}

func (ph *phone) spkiB64(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	ph.must(err)
	return base64.StdEncoding.EncodeToString(der)
}

func rpcError(code int, msg string) error {
	return &MessageError{Msg: fmt.Sprintf("rpc error %d: %s", code, msg)}
}

func notApplicable(map[string]interface{}) (interface{}, error) {
	return nil, rpcError(-32036, "not applicable on this platform")
}

func param(params map[string]interface{}, key string) string {
	value, _ := params[key].(string)
	return value
}

func paramBytes(params map[string]interface{}, key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(param(params, key))
}

func b64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func (ph *phone) generateKey(params map[string]interface{}) (interface{}, error) {
	id := param(params, "keyId")
	switch param(params, "algorithm") {
	case "ES256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ph.must(err)
		shareable, _ := params["shareable"].(bool)
		ph.ecKeys[id] = key
		ph.shareable[id] = shareable
		return map[string]interface{}{"keyId": id, "publicKeyDer": ph.spkiB64(&key.PublicKey)}, nil
	case "AES-256", "AES256-GCM", "HMAC-SHA256":
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		ph.must(err)
		ph.aesKeys[id] = secret
		return map[string]interface{}{"keyId": id}, nil
	}
	return nil, rpcError(-32602, "unsupported algorithm")
}

func (ph *phone) gcm(keyID string) (cipher.AEAD, error) {
	secret, ok := ph.aesKeys[keyID]
	if !ok {
		return nil, rpcError(-32004, "key not found")
	}
	block, err := aes.NewCipher(secret)
	ph.must(err)
	// The random-nonce AEAD seals to nonce || ciphertext || tag, the layout
	// the phone returns, and is the GCM mode FIPS 140-3 approves.
	return cipher.NewGCMWithRandomNonce(block)
}

func (ph *phone) symmetricEncrypt(params map[string]interface{}) (interface{}, error) {
	aead, err := ph.gcm(param(params, "keyId"))
	if err != nil {
		return nil, err
	}
	plaintext, err := paramBytes(params, "data")
	if err != nil {
		return nil, rpcError(-32602, "data is not base64")
	}
	return map[string]interface{}{"data": b64(aead.Seal(nil, nil, plaintext, nil))}, nil
}

func (ph *phone) symmetricDecrypt(params map[string]interface{}) (interface{}, error) {
	aead, err := ph.gcm(param(params, "keyId"))
	if err != nil {
		return nil, err
	}
	sealed, err := paramBytes(params, "data")
	if err != nil || len(sealed) < aead.Overhead() {
		return nil, rpcError(-32602, "data is not a ciphertext")
	}
	plaintext, err := aead.Open(nil, nil, sealed, nil)
	if err != nil {
		return nil, rpcError(-32005, "decryption failed")
	}
	return map[string]interface{}{"data": b64(plaintext)}, nil
}

func (ph *phone) deleteKey(params map[string]interface{}) (interface{}, error) {
	id := param(params, "keyId")
	delete(ph.ecKeys, id)
	delete(ph.aesKeys, id)
	return map[string]interface{}{"deleted": true}, nil
}

func (ph *phone) pinStatus(map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"soPinSet": ph.soPin != "", "userPinSet": ph.userPin != ""}, nil
}

func (ph *phone) pinSet(params map[string]interface{}) (interface{}, error) {
	switch param(params, "pinType") {
	case "SO_PIN":
		ph.soPin = param(params, "newPin")
	case "USER_PIN":
		if param(params, "soPin") != ph.soPin {
			return nil, rpcError(-32010, "SO PIN incorrect")
		}
		ph.userPin = param(params, "newPin")
	default:
		return nil, rpcError(-32602, "unknown pinType")
	}
	return map[string]interface{}{"success": true}, nil
}

func (ph *phone) pinVerify(params map[string]interface{}) (interface{}, error) {
	if param(params, "pin") != ph.userPin {
		return nil, rpcError(-32011, "PIN incorrect")
	}
	return map[string]interface{}{"verified": true}, nil
}

func (ph *phone) pinChange(params map[string]interface{}) (interface{}, error) {
	if param(params, "currentPin") != ph.userPin {
		return nil, rpcError(-32011, "PIN incorrect")
	}
	ph.userPin = param(params, "newPin")
	return map[string]interface{}{"success": true}, nil
}

func (ph *phone) pinResetLockout(params map[string]interface{}) (interface{}, error) {
	if param(params, "soPin") != ph.soPin {
		return nil, rpcError(-32010, "SO PIN incorrect")
	}
	return map[string]interface{}{"success": true}, nil
}

func (ph *phone) pivGenerateKey(map[string]interface{}) (interface{}, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ph.must(err)
	ph.pivKey = key
	return map[string]interface{}{"slot": "9a", "public_key_der": ph.spkiB64(&key.PublicKey)}, nil
}

func (ph *phone) pivListSlots(map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"slots": []string{"9a"}}, nil
}

func (ph *phone) pivSign(params map[string]interface{}) (interface{}, error) {
	data, err := paramBytes(params, "data")
	if err != nil {
		return nil, rpcError(-32602, "data is not base64")
	}
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, ph.pivKey, digest[:])
	ph.must(err)
	return map[string]interface{}{"signature": b64(sig)}, nil
}

func (ph *phone) pivImportCert(params map[string]interface{}) (interface{}, error) {
	der, err := paramBytes(params, "certificate_der")
	if err != nil {
		return nil, rpcError(-32602, "certificate_der is not base64")
	}
	ph.pivCert = der
	return map[string]interface{}{"success": true}, nil
}

func (ph *phone) pivGetCert(map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{"certificate_der": b64(ph.pivCert)}, nil
}

func (ph *phone) oathAdd(params map[string]interface{}) (interface{}, error) {
	credential, ok := params["credential"].(map[string]interface{})
	if !ok {
		return nil, rpcError(-32602, "credential missing")
	}
	ph.oath[param(credential, "name")] = credential
	return map[string]interface{}{"added": true}, nil
}

func (ph *phone) oathList(map[string]interface{}) (interface{}, error) {
	listing := []map[string]interface{}{}
	for name, credential := range ph.oath {
		listing = append(listing, map[string]interface{}{"name": name, "issuer": credential["issuer"]})
	}
	return map[string]interface{}{"credentials": listing}, nil
}

func (ph *phone) oathGenerate(params map[string]interface{}) (interface{}, error) {
	credential, ok := ph.oath[param(params, "credential_id")]
	if !ok {
		return nil, rpcError(-32004, "credential not found")
	}
	digest := sha1.New
	if param(credential, "algorithm") == "SHA256" {
		digest = sha256.New
	}
	return map[string]interface{}{"code": totp(param(credential, "secret"), time.Now().Unix()/30, digest)}, nil
}

func (ph *phone) oathRemove(params map[string]interface{}) (interface{}, error) {
	delete(ph.oath, param(params, "credential_id"))
	return map[string]interface{}{"removed": true}, nil
}

func (ph *phone) createBackup(params map[string]interface{}) (interface{}, error) {
	data, err := paramBytes(params, "backup_data")
	if err != nil {
		return nil, rpcError(-32602, "backup_data is not base64")
	}
	id := fmt.Sprintf("backup-%d", len(ph.backups)+1)
	ph.backups[id] = data
	return map[string]interface{}{"backup_id": id}, nil
}

func (ph *phone) restoreBackup(params map[string]interface{}) (interface{}, error) {
	data, ok := ph.backups[param(params, "backup_id")]
	if !ok {
		return nil, rpcError(-32004, "backup not found")
	}
	return map[string]interface{}{"backup_data": b64(data)}, nil
}

func (ph *phone) sharePublicKey(params map[string]interface{}) (interface{}, error) {
	if block, _ := pem.Decode([]byte(param(params, "public_key_pem"))); block == nil {
		return nil, rpcError(-32602, "public_key_pem is not PEM")
	}
	return map[string]interface{}{"stored": true}, nil
}

func (ph *phone) shareSymmetric(params map[string]interface{}) (interface{}, error) {
	ph.inbound[param(params, "label")] = true
	return map[string]interface{}{"stored": true}, nil
}

// importSharedKey enforces the sharing policy the probe checks: inbound keys
// are never re-exported, and a hardware key exports its public half only.
func (ph *phone) importSharedKey(params map[string]interface{}) (interface{}, error) {
	id := param(params, "key_id")
	if ph.inbound[id] {
		return nil, rpcError(-32003, "inbound shared keys are not exportable")
	}
	key, ok := ph.ecKeys[id]
	if !ok || !ph.shareable[id] {
		return nil, rpcError(-32003, "sharing policy refuses the export")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	ph.must(err)
	return map[string]interface{}{
		"key_id":         id,
		"exportable":     false,
		"public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})),
	}, nil
}

// enrollmentRequest answers as a handset with a TEE: a fresh device key,
// attested under the phone's root over the caller's nonce, and a CSR for it.
func (ph *phone) enrollmentRequest(params map[string]interface{}) (interface{}, error) {
	nonce, err := paramBytes(params, "nonce")
	if err != nil {
		return nil, rpcError(-32602, "nonce is not base64")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ph.must(err)
	ph.deviceKey = key

	leaf := attesttest.AttestedLeafDER(ph.t, ph.attestCA, key, nonce,
		xkms.AndroidSecurityLevelStrongBox, attesttest.AttestedBootState())
	csr, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "e2eprobe device"}}, key)
	ph.must(err)

	res := &pairingproto.LocalGetDeviceEnrollmentRequestResult{
		Format:           pairingproto.AttestationFormatAndroidKey,
		CSR:              csr,
		AttestationChain: []string{b64(leaf), b64(ph.attestCA.Cert.Raw)},
		SecurityLevel:    "strongbox",
	}
	if ph.mutateEnrollment != nil {
		ph.mutateEnrollment(res)
	}
	return res, nil
}

// storeDeviceCredential adopts a certificate only if it is for the device key.
func (ph *phone) storeDeviceCredential(params map[string]interface{}) (interface{}, error) {
	der, err := paramBytes(params, "certificate")
	if err != nil {
		return nil, rpcError(-32602, "certificate is not base64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, rpcError(-32602, "certificate does not parse")
	}
	spki, err := x509.MarshalPKIXPublicKey(&ph.deviceKey.PublicKey)
	ph.must(err)
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, spki) {
		return nil, rpcError(-32602, "certificate is not for the device key")
	}
	return &pairingproto.LocalStoreDeviceCredentialResult{Stored: true, NotAfter: cert.NotAfter.UnixMilli()}, nil
}

// stepNamed returns the step the probe recorded under name.
func stepNamed(t *testing.T, p *prober, name string) step {
	t.Helper()
	for _, s := range p.steps {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no step %q recorded; steps: %+v", name, p.steps)
	return step{}
}

// requireFailedStep checks the probe recorded name as failed, with a detail
// that says why.
func requireFailedStep(t *testing.T, p *prober, name, wantDetail string) step {
	t.Helper()
	s := stepNamed(t, p, name)
	if s.ok {
		t.Fatalf("step %q passed; want it to fail with %q", name, wantDetail)
	}
	if !strings.Contains(s.detail, wantDetail) {
		t.Fatalf("step %q detail = %q, want it to contain %q", name, s.detail, wantDetail)
	}
	return s
}

func failedSteps(p *prober) []string {
	var failed []string
	for _, s := range p.steps {
		if !s.ok {
			failed = append(failed, s.name+s.detail)
		}
	}
	return failed
}

func TestFamilies_PassAgainstAConformantPhone(t *testing.T) {
	tests := []struct {
		name     string
		run      func(p *prober)
		lastStep string
	}{
		{"symmetric round-trip", func(p *prober) { symRoundtrip(p, "hw", "aes-key", false) },
			"local.symmetricDecrypt round-trip (hw)"},
		{"pin", pinFamily, "local.pinResetLockout"},
		{"piv", func(p *prober) { pivFamily(p, "run") }, "local.pivGetCert (round-trip)"},
		{"oath", func(p *prober) { oathFamily(p, "run") }, "local.oathRemove"},
		{"backup", backupFamily, "local.restoreBackup (round-trip)"},
		{"sharing", func(p *prober) { sharingFamily(p, "run", "hw-key") },
			"local.importSharedKey (hardware public-only)"},
		{"enrollment", enrollmentFamily, "credential was adopted"},
		{"tpm refusal", tpmRefusalFamily, pairingproto.MethodLocalGetIAKPublicKey + " is refused as not applicable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newPhone(t).prober()
			tt.run(p)

			if failed := failedSteps(p); len(failed) > 0 {
				t.Fatalf("steps failed against a conformant phone: %v", failed)
			}
			// The family must reach its final check, not pass by stopping early.
			stepNamed(t, p, tt.lastStep)
		})
	}
}

func TestSymRoundtrip_RecordsPlaintextMismatch(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.symmetricDecrypt"] = func(map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{"data": b64([]byte("not what was encrypted"))}, nil
	}
	p := ph.prober()

	symRoundtrip(p, "hw", "aes-key", false)

	requireFailedStep(t, p, "local.symmetricDecrypt round-trip (hw)", "round-trip mismatch")
	if len(ph.aesKeys) != 0 {
		t.Fatal("the probe key was left on the phone after a failed round-trip")
	}
}

func TestSymRoundtrip_RecordsMalformedCiphertext(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.symmetricEncrypt"] = func(map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{"data": 42}, nil
	}
	p := ph.prober()

	symRoundtrip(p, "sw exportable", "aes-key", true)

	requireFailedStep(t, p, "local.symmetricDecrypt round-trip (sw exportable)", "malformed symmetricEncrypt response")
	if ph.called("local.symmetricDecrypt") {
		t.Fatal("decrypt was attempted with a ciphertext the phone never produced")
	}
}

func TestSymRoundtrip_StopsWhenKeyGenerationFails(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.generateKey"] = func(map[string]interface{}) (interface{}, error) {
		return nil, rpcError(-32000, "keystore unavailable")
	}
	p := ph.prober()

	symRoundtrip(p, "hw", "aes-key", false)

	if len(p.steps) != 1 {
		t.Fatalf("recorded %d steps, want only the failed generateKey", len(p.steps))
	}
	requireFailedStep(t, p, "local.generateKey (AES-256 hw)", "keystore unavailable")
	if ph.called("local.symmetricEncrypt") {
		t.Fatal("encrypt was attempted without a key")
	}
}

func TestPinFamily_FailsWhenThePhoneAcceptsAWrongPIN(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.pinVerify"] = func(map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{"verified": true}, nil
	}
	p := ph.prober()

	pinFamily(p)

	requireFailedStep(t, p, "local.pinVerify rejects wrong PIN", "wrong PIN accepted")
}

func TestPinFamily_UserPINRefusalAfterAnEarlierRunIsOptional(t *testing.T) {
	ph := newPhone(t)
	ph.soPin = "11112222" // left behind by an earlier run
	p := ph.prober()

	pinFamily(p)

	s := requireFailedStep(t, p, "local.pinSet (USER_PIN)", "SO PIN from a previous run?")
	if s.required {
		t.Fatal("a USER_PIN refusal caused by a stale SO PIN must not fail the run")
	}
	if ph.called("local.pinVerify") {
		t.Fatal("the PIN family continued without a USER PIN")
	}
}

func TestPinFamily_StopsWhenStatusFails(t *testing.T) {
	ph := newPhone(t)
	delete(ph.handlers, "local.pinStatus")
	p := ph.prober()

	pinFamily(p)

	if len(p.steps) != 1 {
		t.Fatalf("recorded %d steps, want only the failed pinStatus", len(p.steps))
	}
	requireFailedStep(t, p, "local.pinStatus", "-32601")
}

func TestPivFamily_RejectsASignatureFromAnotherKey(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.pivSign"] = func(params map[string]interface{}) (interface{}, error) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ph.must(err)
		data, err := paramBytes(params, "data")
		ph.must(err)
		digest := sha256.Sum256(data)
		sig, err := ecdsa.SignASN1(rand.Reader, other, digest[:])
		ph.must(err)
		return map[string]interface{}{"signature": b64(sig)}, nil
	}
	p := ph.prober()

	pivFamily(p, "run")

	requireFailedStep(t, p, "verify PIV signature (Go side)", "PIV signature does not verify")
}

func TestPivFamily_RecordsCertificateMismatch(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.pivGetCert"] = func(map[string]interface{}) (interface{}, error) {
		other, err := selfSignedCert("someone else")
		ph.must(err)
		return map[string]interface{}{"certificate_der": b64(other)}, nil
	}
	p := ph.prober()

	pivFamily(p, "run")

	requireFailedStep(t, p, "local.pivGetCert (round-trip)", "certificate round-trip mismatch")
}

func TestOathFamily_RejectsACodeGoDoesNotCompute(t *testing.T) {
	ph := newPhone(t)
	ph.handlers["local.oathGenerate"] = func(map[string]interface{}) (interface{}, error) {
		return map[string]interface{}{"code": "phone-made"}, nil
	}
	p := ph.prober()

	oathFamily(p, "run")

	requireFailedStep(t, p, "TOTP cross-compute (Go side)", "TOTP mismatch")
	if len(ph.oath) != 0 {
		t.Fatal("the probe credential was left on the phone")
	}
}

func TestOathFamily_RecordsDeviantListingsAndCodes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		answer     map[string]interface{}
		step       string
		wantDetail string
	}{
		{"credential absent from the listing", "local.oathList", map[string]interface{}{"credentials": []interface{}{}},
			"find added OATH credential", "credential not in listing"},
		{"listing is not an array", "local.oathList", map[string]interface{}{"credentials": "none"},
			"find added OATH credential", "malformed oathList response"},
		{"code is not a string", "local.oathGenerate", map[string]interface{}{"code": 123456},
			"TOTP cross-compute (Go side)", "malformed oathGenerate response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := newPhone(t)
			ph.handlers[tt.method] = func(map[string]interface{}) (interface{}, error) { return tt.answer, nil }
			p := ph.prober()

			oathFamily(p, "run")

			requireFailedStep(t, p, tt.step, tt.wantDetail)
		})
	}
}

func TestBackupFamily_RecordsDeviantRestores(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		answer     map[string]interface{}
		wantDetail string
	}{
		{"restored bytes differ", "local.restoreBackup",
			map[string]interface{}{"backup_data": b64([]byte("other"))}, "backup round-trip mismatch"},
		{"backup id is not a string", "local.createBackup",
			map[string]interface{}{"backup_id": 7}, "malformed createBackup response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := newPhone(t)
			ph.handlers[tt.method] = func(map[string]interface{}) (interface{}, error) { return tt.answer, nil }
			p := ph.prober()

			backupFamily(p)

			requireFailedStep(t, p, "local.restoreBackup (round-trip)", tt.wantDetail)
		})
	}
}

func TestBackupFamily_StopsWhenCreateFails(t *testing.T) {
	ph := newPhone(t)
	delete(ph.handlers, "local.createBackup")
	p := ph.prober()

	backupFamily(p)

	requireFailedStep(t, p, "local.createBackup", "-32601")
	if ph.called("local.restoreBackup") {
		t.Fatal("restore was attempted without a backup")
	}
}

func TestSharingFamily_FailsWhenAnInboundKeyIsReexported(t *testing.T) {
	ph := newPhone(t)
	original := ph.handlers["local.importSharedKey"]
	ph.handlers["local.importSharedKey"] = func(params map[string]interface{}) (interface{}, error) {
		if ph.inbound[param(params, "key_id")] {
			return map[string]interface{}{"wrapped_key": b64([]byte("material"))}, nil
		}
		return original(params)
	}
	p := ph.prober()

	sharingFamily(p, "run", "hw-key")

	requireFailedStep(t, p, "local.importSharedKey refuses an inbound shared key", "must be refused")
}

func TestSharingFamily_FailsWhenAHardwareKeyExportsMoreThanItsPublicHalf(t *testing.T) {
	tests := []struct {
		name       string
		answer     map[string]interface{}
		wantDetail string
	}{
		{"reported exportable", map[string]interface{}{"exportable": true}, "hardware key reported exportable"},
		{"leaked wrapped key", map[string]interface{}{"exportable": false, "wrapped_key": "AAAA"},
			"hardware key leaked wrapped_key"},
		{"exportable is not a bool", map[string]interface{}{"exportable": "no"}, "malformed importSharedKey response"},
		{"exportable missing", map[string]interface{}{}, "malformed importSharedKey response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := newPhone(t)
			original := ph.handlers["local.importSharedKey"]
			ph.handlers["local.importSharedKey"] = func(params map[string]interface{}) (interface{}, error) {
				if ph.inbound[param(params, "key_id")] {
					return original(params)
				}
				return tt.answer, nil
			}
			p := ph.prober()

			sharingFamily(p, "run", "hw-key")

			requireFailedStep(t, p, "local.importSharedKey (hardware public-only)", tt.wantDetail)
			if len(ph.ecKeys) != 0 {
				t.Fatal("the shareable probe key was left on the phone")
			}
		})
	}
}

func TestTPMRefusalFamily_RequiresASpecificNotApplicableRefusal(t *testing.T) {
	tests := []struct {
		name       string
		answer     phoneHandler
		wantDetail string
	}{
		{"phone answers the method", func(map[string]interface{}) (interface{}, error) {
			return map[string]interface{}{"quote": "AAAA"}, nil
		}, "answered a TPM2 method it cannot implement"},
		{"phone reports method not found", func(map[string]interface{}) (interface{}, error) {
			return nil, rpcError(-32601, "method not found")
		}, "expected NOT_APPLICABLE (-32036)"},
	}
	methods := []string{
		pairingproto.MethodLocalGetTCGCSRIDevID,
		pairingproto.MethodLocalActivateCredential,
		pairingproto.MethodLocalGetAttestationQuote,
		pairingproto.MethodLocalGetIAKPublicKey,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := newPhone(t)
			for _, method := range methods {
				ph.handlers[method] = tt.answer
			}
			p := ph.prober()

			tpmRefusalFamily(p)

			for _, method := range methods {
				s := requireFailedStep(t, p, method+" is refused as not applicable", tt.wantDetail)
				if !s.required {
					t.Fatalf("%s: a wrong TPM2 refusal must fail the run", method)
				}
			}
		})
	}
}

func TestRecord_AppendsTheErrorToTheDetail(t *testing.T) {
	p := &prober{}

	p.record("passes", true, nil, "info")
	p.record("fails", false, &MessageError{Msg: "boom"}, "info")

	if s := p.steps[0]; !s.ok || !s.required || s.detail != "info" {
		t.Fatalf("passing step = %+v", s)
	}
	if s := p.steps[1]; s.ok || s.required || s.detail != "info -> boom" {
		t.Fatalf("failing step = %+v", s)
	}
}

func TestRequiredCall_ReturnsTheResultOnlyOnSuccess(t *testing.T) {
	ph := newPhone(t)
	p := ph.prober()

	if out := p.requiredCall("status", "local.pinStatus", nil); out == nil {
		t.Fatal("requiredCall returned nil for a successful call")
	}
	if out := p.requiredCall("missing", "local.nope", nil); out != nil {
		t.Fatalf("requiredCall returned %v for a failed call", out)
	}
	if !p.steps[0].ok || p.steps[1].ok || !p.steps[1].required {
		t.Fatalf("steps = %+v", p.steps)
	}
}

func TestRequireNonEmptyAndNonZero(t *testing.T) {
	if err := requireNonEmpty("deviceName", "pixel"); err != nil {
		t.Fatalf("requireNonEmpty(non-empty) = %v", err)
	}
	if err := requireNonZero("maxKeys", 3); err != nil {
		t.Fatalf("requireNonZero(3) = %v", err)
	}
	if err := requireNonEmpty("deviceName", ""); err == nil || !strings.Contains(err.Error(), "deviceName") {
		t.Fatalf("requireNonEmpty(empty) = %v, want an error naming the field", err)
	}
	if err := requireNonZero("maxKeys", 0); err == nil || !strings.Contains(err.Error(), "maxKeys") {
		t.Fatalf("requireNonZero(0) = %v, want an error naming the field", err)
	}
}

func TestDecodeB64(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want []byte
	}{
		{"base64 string", json.RawMessage(`"aGk="`), []byte("hi")},
		{"not a JSON string", json.RawMessage(`42`), nil},
		{"not base64", json.RawMessage(`"!!"`), nil},
		{"absent field", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeB64(tt.raw); !bytes.Equal(got, tt.want) {
				t.Fatalf("decodeB64(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestSelfSignedCert_IsSelfSignedForTheName(t *testing.T) {
	der, err := selfSignedCert("probe-cn")
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cert.Subject.CommonName != "probe-cn" {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("certificate is not self-signed: %v", err)
	}
}
