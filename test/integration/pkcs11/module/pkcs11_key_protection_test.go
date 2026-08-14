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

//go:build integration

package module

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/unix"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

// dialDaemon opens a transport client to the same xkmsd the module under test is
// talking to, independent of the module itself.
//
// Tests that only drive the module can never see a disagreement between what the
// module believes about a key and what the daemon recorded, because every answer
// they get is the module's. Asking the daemon directly is the only way to observe
// its own record -- and it is also the position a real attacker occupies, since
// the module's object store is client-side state while the daemon's is not.
func dialDaemon(t *testing.T) transport.Client {
	t.Helper()

	socketPath := os.Getenv("XKMS_UNIX_SOCKET")
	if socketPath == "" {
		socketPath = "/var/run/xkms/xkms.sock"
	}

	client, err := unix.New(transport.WithAddress(socketPath))
	if err != nil {
		t.Fatalf("could not create a transport client for %s: %v", socketPath, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("could not connect to xkmsd at %s: %v", socketPath, err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client
}

// daemonKeyFor finds the daemon-side key record the module created for a
// C_GenerateKey call made with the given CKA_LABEL.
//
// Module.GenerateKey derives the backend key identifier as
// "<label>-<nanos>-<counter>", so a label unique to the test identifies exactly
// one key by prefix. Returning the backend name alongside it keeps the caller
// from having to guess which backend the module defaulted to.
func daemonKeyFor(t *testing.T, client transport.Client, label string) (keyID, backend string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The backend has to be named: the unix transport refuses an empty one
	// ("backend is required"), and it is the backend the module generated into.
	// module.DefaultBackend is that backend unless the environment overrides it,
	// which is the same resolution Config.applyDefaults performs.
	backendName := os.Getenv(module.EnvDefaultBackend)
	if backendName == "" {
		backendName = module.DefaultBackend
	}

	resp, err := client.ListKeys(ctx, backendName)
	if err != nil {
		t.Fatalf("ListKeys against the daemon for backend %q failed: %v", backendName, err)
	}
	for _, key := range resp.Keys {
		if strings.HasPrefix(key.KeyID, label) {
			backend := key.Backend
			if backend == "" {
				backend = backendName
			}
			return key.KeyID, backend
		}
	}

	t.Fatalf("backend %q holds no key whose identifier begins with %q; "+
		"C_GenerateKey reported success, so the key should be on the backend", backendName, label)
	return "", ""
}

// buildBareAESTemplate is a C_GenerateKey template that names no protection
// attributes at all: no CKA_SENSITIVE and no CKA_EXTRACTABLE.
//
// This is the case the token itself has to decide, and it is what
// pkcs11-tool --keygen sends by default, so it is also the template most real
// applications produce.
func buildBareAESTemplate(label string) []module.Attribute {
	return []module.Attribute{
		module.NewUint32Attribute(module.CKA_CLASS, uint32(module.CKO_SECRET_KEY)),
		module.NewUint32Attribute(module.CKA_KEY_TYPE, uint32(module.CKK_AES)),
		module.NewStringAttribute(module.CKA_LABEL, label),
		module.NewUint32Attribute(module.CKA_VALUE_LEN, 32),
		module.NewBoolAttribute(module.CKA_TOKEN, true),
		module.NewBoolAttribute(module.CKA_ENCRYPT, true),
		module.NewBoolAttribute(module.CKA_DECRYPT, true),
	}
}

// boolAttributeValue reads a CK_BBOOL attribute off an object, failing the test
// if it is absent or was withheld.
func boolAttributeValue(t *testing.T, env *TestEnvironment, session module.SessionHandle,
	handle module.ObjectHandle, attrType module.AttributeType, what string) bool {
	t.Helper()

	attrs, rv := env.Module.GetAttributeValue(session, handle, []module.Attribute{{Type: attrType}})
	RequireOK(t, rv, "C_GetAttributeValue "+what)
	if len(attrs) != 1 {
		t.Fatalf("C_GetAttributeValue(%s) returned %d attributes, want 1", what, len(attrs))
	}
	if attrs[0].Unavailable {
		t.Fatalf("C_GetAttributeValue(%s) reported the attribute unavailable", what)
	}
	if len(attrs[0].Value) == 0 {
		t.Fatalf("C_GetAttributeValue(%s) returned an empty value", what)
	}
	return attrs[0].Value[0] != 0
}

// TestBareTemplateGeneratesAProtectedKey pins the token's choice of protection
// defaults against a real xkmsd, which is the only place the choice is fully
// observable.
//
// PKCS#11 v3.2 Table 30 gives CKA_EXTRACTABLE no default; footnote 9 makes it
// "token-specific, and may depend on the values of other attributes". This token
// chooses the protective values, matching SoftHSM2: a bare
// pkcs11-tool --keygen --key-type aes:32 there produces a key reporting "never
// extractable" whose CKA_VALUE reads back as CKR_ATTRIBUTE_SENSITIVE.
//
// The unit suite cannot settle this on its own. The module sends its decision to
// the daemon at generation time and the daemon records it on the key; a defect
// that agreed with the object but disagreed with the wire -- which is exactly
// the defect this test was written for, where the request was built from the
// undefaulted template and the object from the defaulted one -- looks correct to
// any check that only reads the module's own object back.
func TestBareTemplateGeneratesAProtectedKey(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	label := uniqueLabel("bare-template-protection")
	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN}, buildBareAESTemplate(label))
	RequireOK(t, rv, "C_GenerateKey with a bare template")

	if sensitive := boolAttributeValue(t, env, session, handle,
		module.CKA_SENSITIVE, "CKA_SENSITIVE"); !sensitive {
		t.Error("a template that named no protection attributes produced CKA_SENSITIVE=CK_FALSE; " +
			"the token must choose the protective value, since v3.2 footnote 11 makes " +
			"CKA_SENSITIVE a one-way ratchet the application can still tighten but never loosen")
	}

	if extractable := boolAttributeValue(t, env, session, handle,
		module.CKA_EXTRACTABLE, "CKA_EXTRACTABLE"); extractable {
		t.Error("a template that named no protection attributes produced CKA_EXTRACTABLE=CK_TRUE; " +
			"Table 30 gives the attribute no default and footnote 9 leaves the choice to the token, " +
			"which must not spend the footnote 12 ratchet on the application's behalf")
	}
}

// TestBareTemplateKeyWithholdsItsValueFromTheDaemon is the half that only a real
// daemon can prove.
//
// The previous test reads the module's own object. This one asks for the key's
// material, which the module does not hold: C_GenerateKey creates it inside the
// backend, so answering CKA_VALUE means asking xkmsd to release it. That request
// is refused on the daemon's own record of the key rather than on the module's
// attribute, which is the property that makes CKA_SENSITIVE mean anything to a
// caller who can edit the module's local state.
//
// v3.2 §4.9 footnote 7 is the rule being checked: a value "cannot be revealed if
// object has its CKA_SENSITIVE attribute set to CK_TRUE or its CKA_EXTRACTABLE
// attribute set to CK_FALSE". A bare-template key satisfies both halves.
func TestBareTemplateKeyWithholdsItsValueFromTheDaemon(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	label := uniqueLabel("bare-template-value")
	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN}, buildBareAESTemplate(label))
	RequireOK(t, rv, "C_GenerateKey with a bare template")

	attrs, rv := env.Module.GetAttributeValue(session, handle,
		[]module.Attribute{{Type: module.CKA_VALUE}})

	if rv == module.CKR_OK && len(attrs) == 1 && !attrs[0].Unavailable && len(attrs[0].Value) > 0 {
		t.Fatalf("C_GetAttributeValue(CKA_VALUE) released %d bytes of key material for a key "+
			"generated from a bare template; footnote 7 withholds the value of a key that is "+
			"CKA_SENSITIVE or not CKA_EXTRACTABLE, and this key is both", len(attrs[0].Value))
	}

	if rv != module.CKR_ATTRIBUTE_SENSITIVE {
		t.Errorf("C_GetAttributeValue(CKA_VALUE) returned %s, want CKR_ATTRIBUTE_SENSITIVE; "+
			"the refusal must name the reason the value is withheld", rv.String())
	}
}

// TestExplicitlyUnprotectedKeyStillReleasesItsValue is the counterweight.
//
// Without it, a module that refused every CKA_VALUE request would pass the two
// tests above while breaking every application that legitimately generates a
// readable key. The template here says CKA_SENSITIVE=CK_FALSE and
// CKA_EXTRACTABLE=CK_TRUE, so footnote 7 does not apply and the daemon has no
// grounds to withhold anything -- which also proves the protective default is a
// default and not a hard-coded refusal.
func TestExplicitlyUnprotectedKeyStillReleasesItsValue(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	label := uniqueLabel("explicit-readable")
	template := append(buildBareAESTemplate(label),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
	)

	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN}, template)
	RequireOK(t, rv, "C_GenerateKey with an explicitly unprotected template")

	attrs, rv := env.Module.GetAttributeValue(session, handle,
		[]module.Attribute{{Type: module.CKA_VALUE}})
	RequireOK(t, rv, "C_GetAttributeValue(CKA_VALUE) on an explicitly readable key")

	if len(attrs) != 1 || attrs[0].Unavailable {
		t.Fatal("C_GetAttributeValue(CKA_VALUE) withheld the value of a key whose own attributes " +
			"say it may be revealed; the protective default must be a default, not a refusal")
	}
	if len(attrs[0].Value) != 32 {
		t.Errorf("C_GetAttributeValue(CKA_VALUE) returned %d bytes, want 32 for an AES-256 key",
			len(attrs[0].Value))
	}
}

// TestSensitiveButExtractableKeyWithholdsItsValue covers the half of footnote 7
// that CKA_SENSITIVE carries on its own.
//
// A key generated CKA_SENSITIVE=CK_TRUE and CKA_EXTRACTABLE=CK_TRUE is the
// ordinary combination for a wrappable-but-unreadable key, and it separates the
// two rules: the value is withheld because of CKA_SENSITIVE alone, while
// CKA_EXTRACTABLE=CK_TRUE means the key may still leave the token through
// C_WrapKey. The other integration cases here are all CKA_EXTRACTABLE=CK_FALSE,
// where either half of footnote 7 would explain the refusal.
//
// What this does NOT prove is that the daemon refuses. The module answers first:
// Object.protectsSensitiveAttributes is CKA_SENSITIVE || !CKA_EXTRACTABLE, so a
// sensitive key never reaches the wire and no request is made. That is correct
// behaviour -- a token should not ask its backend for something it already knows
// it may not reveal -- but it means this test exercises the module's copy of the
// rule, not the daemon's.
//
// The daemon-side refusal is the one that matters when the module's copy has
// been tampered with, and it cannot be reached from here precisely because the
// module short-circuits. It is covered by
// TestExportKeyMaterialRefusesSensitiveKeys in pkg/xkms, which calls the service
// layer directly with a key recorded sensitive. The two together are the
// defence-in-depth pair: module first, daemon regardless.
func TestSensitiveButExtractableKeyWithholdsItsValue(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	label := uniqueLabel("sensitive-but-extractable")
	template := append(buildBareAESTemplate(label),
		module.NewBoolAttribute(module.CKA_SENSITIVE, true),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
	)

	handle, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN}, template)
	RequireOK(t, rv, "C_GenerateKey for a sensitive but extractable key")

	if extractable := boolAttributeValue(t, env, session, handle,
		module.CKA_EXTRACTABLE, "CKA_EXTRACTABLE"); !extractable {
		t.Fatal("the template asked for CKA_EXTRACTABLE=CK_TRUE; without it this case does not " +
			"distinguish the sensitivity rule from the extractability rule")
	}

	attrs, rv := env.Module.GetAttributeValue(session, handle,
		[]module.Attribute{{Type: module.CKA_VALUE}})
	if rv == module.CKR_OK && len(attrs) == 1 && !attrs[0].Unavailable && len(attrs[0].Value) > 0 {
		t.Fatalf("C_GetAttributeValue(CKA_VALUE) released %d bytes for a CKA_SENSITIVE key",
			len(attrs[0].Value))
	}
}

// TestDaemonRecordsTheProtectionTheTokenChose is the test that catches a module
// whose wire request disagrees with the object it created.
//
// Every other case in this file reads the module's own answers, and the module
// is self-consistent under the defect this was written for: C_GenerateKey built
// its GenerateKeyRequest from the caller's raw template with a CK_TRUE
// exportability fallback, then applied secretKeyProtectionDefaults -- whose
// fallback is the opposite -- to the object it stored. The object said
// CKA_EXTRACTABLE=CK_FALSE and the daemon's key record said exportable, and no
// test driving the module could tell, because C_GetAttributeValue answers from
// the object and Object.protectsSensitiveAttributes short-circuits the CKA_VALUE
// request before it ever reaches the wire.
//
// So this asks the daemon, over its own connection, to hand over the key's
// plaintext. Under the defect the daemon believed the key was exportable and
// obliged; a bare-template key -- the template pkcs11-tool --keygen sends by
// default -- was therefore readable by anyone who could reach xkmsd, whatever
// the token told the application about it.
func TestDaemonRecordsTheProtectionTheTokenChose(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	label := uniqueLabel("daemon-record-protection")
	if _, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN}, buildBareAESTemplate(label)); rv != module.CKR_OK {
		RequireOK(t, rv, "C_GenerateKey with a bare template")
	}

	client := dialDaemon(t)
	keyID, backend := daemonKeyFor(t, client, label)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		KeyID:   keyID,
		Backend: backend,
	})

	if err == nil && resp != nil && len(resp.KeyMaterial) > 0 {
		t.Fatalf("the daemon released %d bytes of plaintext for key %q, which the token "+
			"created from a bare template and reported to the application as "+
			"CKA_SENSITIVE=CK_TRUE, CKA_EXTRACTABLE=CK_FALSE; the record the daemon keeps "+
			"must carry the same protection the token chose", len(resp.KeyMaterial), keyID)
	}
}

// TestDaemonStillExportsAKeyTheApplicationAskedToBeReadable is the counterweight
// to the test above, at the same observation point.
//
// A daemon that refused every export would pass that test while breaking the
// BYOK and key-escrow paths that ExportKeyMaterial exists to serve. This
// template explicitly says CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE,
// so the daemon's record must permit exactly what the application asked for --
// which also proves the refusal above tracks the template rather than being
// unconditional.
func TestDaemonStillExportsAKeyTheApplicationAskedToBeReadable(t *testing.T) {
	env, session := SetupAuthenticatedModule(t)

	label := uniqueLabel("daemon-record-readable")
	template := append(buildBareAESTemplate(label),
		module.NewBoolAttribute(module.CKA_SENSITIVE, false),
		module.NewBoolAttribute(module.CKA_EXTRACTABLE, true),
	)
	if _, rv := env.Module.GenerateKey(session,
		&module.Mechanism{Type: module.CKM_AES_KEY_GEN}, template); rv != module.CKR_OK {
		RequireOK(t, rv, "C_GenerateKey with an explicitly unprotected template")
	}

	client := dialDaemon(t)
	keyID, backend := daemonKeyFor(t, client, label)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		KeyID:   keyID,
		Backend: backend,
	})
	if err != nil {
		t.Fatalf("the daemon refused to export key %q, which the application generated with "+
			"CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE: %v", keyID, err)
	}
	if len(resp.KeyMaterial) != 32 {
		t.Errorf("the daemon returned %d bytes for an AES-256 key, want 32", len(resp.KeyMaterial))
	}
}
