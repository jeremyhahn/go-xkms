/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of go-xkms.
 *
 * go-xkms is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

/*
 * xkabi.h dispatches Cryptoki calls through a CK_FUNCTION_LIST_3_2 obtained
 * from a dlopen()ed module.
 *
 * Every wrapper is static inline and lives in a header rather than in one Go
 * file's cgo preamble because cgo compiles each preamble as its own
 * translation unit: a static function defined in one Go file's preamble is not
 * linkable from another's. Sharing them through a header gives each unit its
 * own copy and keeps the whole package on one definition.
 *
 * Dispatching through the list, rather than through symbols resolved directly
 * out of the shared object with dlsym, is deliberate. A module whose exported
 * C_Sign is correct but whose function-list slot points elsewhere would pass
 * the dlsym style of test and fail in every real application, because
 * applications only ever reach the module through this table.
 */

#ifndef XKMS_TEST_XKABI_H
#define XKMS_TEST_XKABI_H

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include "pkcs11.h"

typedef CK_RV (*xk_getinterface_fn)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS);

/* xk_get_interface resolves and invokes C_GetInterface out of a dlopen()ed
 * module. Requesting the interface by name and version is the v3.x entry point
 * (PKCS#11 v3.2 section 5.3); C_GetFunctionList can only hand back the v2.40
 * list, which has no message-based functions at all. */
static inline CK_RV xk_get_interface(void *handle, char *name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out) {
	xk_getinterface_fn fn = (xk_getinterface_fn)dlsym(handle, "C_GetInterface");
	if (fn == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return fn((CK_UTF8CHAR_PTR)name, version, out, 0);
}

/* xk_interface_list exposes CK_INTERFACE.pFunctionList, which Go cannot reach
 * through the opaque pointer on its own. */
static inline CK_VOID_PTR xk_interface_list(CK_INTERFACE_PTR iface) { return iface->pFunctionList; }

typedef CK_RV (*xk_getfunctionlist_fn)(CK_FUNCTION_LIST_PTR_PTR);

/* xk_get_function_list resolves and invokes the v2.40 C_GetFunctionList entry
 * point, which every conforming module exports regardless of version. It is
 * the fallback that lets this harness also drive a v2.40 reference
 * implementation such as SoftHSM2. */
static inline CK_RV xk_get_function_list(void *handle, CK_FUNCTION_LIST_PTR_PTR out) {
	xk_getfunctionlist_fn fn = (xk_getfunctionlist_fn)dlsym(handle, "C_GetFunctionList");
	if (fn == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return fn(out);
}

/* ---- session and token management ---- */

static inline CK_RV xk_Initialize(CK_FUNCTION_LIST_3_2_PTR fl, CK_VOID_PTR args) {
	return fl->C_Initialize(args);
}
static inline CK_RV xk_Finalize(CK_FUNCTION_LIST_3_2_PTR fl, CK_VOID_PTR reserved) {
	return fl->C_Finalize(reserved);
}
static inline CK_RV xk_GetSlotList(CK_FUNCTION_LIST_3_2_PTR fl, CK_BBOOL present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count) {
	return fl->C_GetSlotList(present, slots, count);
}
static inline CK_RV xk_GetMechanismList(CK_FUNCTION_LIST_3_2_PTR fl, CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
	return fl->C_GetMechanismList(slot, list, count);
}
static inline CK_RV xk_OpenSession(CK_FUNCTION_LIST_3_2_PTR fl, CK_SLOT_ID slot, CK_FLAGS flags, CK_SESSION_HANDLE_PTR session) {
	return fl->C_OpenSession(slot, flags, NULL, NULL, session);
}
static inline CK_RV xk_CloseSession(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session) {
	return fl->C_CloseSession(session);
}
static inline CK_RV xk_Login(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pinLen) {
	return fl->C_Login(session, user, pin, pinLen);
}
static inline CK_RV xk_Logout(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session) {
	return fl->C_Logout(session);
}

/* ---- objects ---- */

static inline CK_RV xk_DestroyObject(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj) {
	return fl->C_DestroyObject(session, obj);
}
static inline CK_RV xk_GetAttributeValue(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count) {
	return fl->C_GetAttributeValue(session, obj, tmpl, count);
}
static inline CK_RV xk_GenerateKey(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
	return fl->C_GenerateKey(session, mech, tmpl, count, key);
}
static inline CK_RV xk_GenerateKeyPair(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
	CK_ATTRIBUTE_PTR pubTmpl, CK_ULONG pubCount, CK_ATTRIBUTE_PTR privTmpl, CK_ULONG privCount,
	CK_OBJECT_HANDLE_PTR pub, CK_OBJECT_HANDLE_PTR priv) {
	return fl->C_GenerateKeyPair(session, mech, pubTmpl, pubCount, privTmpl, privCount, pub, priv);
}

/* ---- signing and verification ---- */

static inline CK_RV xk_SignInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_SignInit(session, mech, key);
}
static inline CK_RV xk_Sign(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen, CK_BYTE_PTR sig, CK_ULONG_PTR sigLen) {
	return fl->C_Sign(session, data, dataLen, sig, sigLen);
}
static inline CK_RV xk_VerifyInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_VerifyInit(session, mech, key);
}
static inline CK_RV xk_Verify(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLen, CK_BYTE_PTR sig, CK_ULONG sigLen) {
	return fl->C_Verify(session, data, dataLen, sig, sigLen);
}

/* ---- encryption and decryption ---- */

static inline CK_RV xk_EncryptInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_EncryptInit(session, mech, key);
}
static inline CK_RV xk_Encrypt(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	return fl->C_Encrypt(session, in, inLen, out, outLen);
}
static inline CK_RV xk_EncryptUpdate(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	return fl->C_EncryptUpdate(session, in, inLen, out, outLen);
}
static inline CK_RV xk_EncryptFinal(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	return fl->C_EncryptFinal(session, out, outLen);
}
static inline CK_RV xk_DecryptInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_DecryptInit(session, mech, key);
}
static inline CK_RV xk_Decrypt(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	return fl->C_Decrypt(session, in, inLen, out, outLen);
}
static inline CK_RV xk_DecryptUpdate(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR in, CK_ULONG inLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	return fl->C_DecryptUpdate(session, in, inLen, out, outLen);
}
static inline CK_RV xk_DecryptFinal(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	return fl->C_DecryptFinal(session, out, outLen);
}

/* ---- key derivation ---- */

static inline CK_RV xk_DeriveKey(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE base, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) {
	return fl->C_DeriveKey(session, mech, base, tmpl, count, key);
}

/* ---- message-based signing (v3.x only) ---- */

static inline CK_RV xk_MessageSignInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_MessageSignInit(session, mech, key);
}
static inline CK_RV xk_SignMessage(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_VOID_PTR param, CK_ULONG paramLen,
	CK_BYTE_PTR data, CK_ULONG dataLen, CK_BYTE_PTR sig, CK_ULONG_PTR sigLen) {
	return fl->C_SignMessage(session, param, paramLen, data, dataLen, sig, sigLen);
}

/* ---- message-based AEAD (v3.x only) ---- */

static inline CK_RV xk_MessageEncryptInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_MessageEncryptInit(session, mech, key);
}
static inline CK_RV xk_EncryptMessage(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_VOID_PTR param, CK_ULONG paramLen,
	CK_BYTE_PTR aad, CK_ULONG aadLen, CK_BYTE_PTR pt, CK_ULONG ptLen, CK_BYTE_PTR ct, CK_ULONG_PTR ctLen) {
	return fl->C_EncryptMessage(session, param, paramLen, aad, aadLen, pt, ptLen, ct, ctLen);
}
static inline CK_RV xk_MessageEncryptFinal(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session) {
	return fl->C_MessageEncryptFinal(session);
}
static inline CK_RV xk_MessageDecryptInit(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key) {
	return fl->C_MessageDecryptInit(session, mech, key);
}
static inline CK_RV xk_DecryptMessage(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_VOID_PTR param, CK_ULONG paramLen,
	CK_BYTE_PTR aad, CK_ULONG aadLen, CK_BYTE_PTR ct, CK_ULONG ctLen, CK_BYTE_PTR pt, CK_ULONG_PTR ptLen) {
	return fl->C_DecryptMessage(session, param, paramLen, aad, aadLen, ct, ctLen, pt, ptLen);
}
static inline CK_RV xk_MessageDecryptFinal(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session) {
	return fl->C_MessageDecryptFinal(session);
}

/* ---- authenticated wrapping (v3.2 only) ---- */

static inline CK_RV xk_CreateObject(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count, CK_OBJECT_HANDLE_PTR obj) {
	return fl->C_CreateObject(session, tmpl, count, obj);
}
static inline CK_RV xk_SetAttributeValue(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR tmpl, CK_ULONG count) {
	return fl->C_SetAttributeValue(session, obj, tmpl, count);
}
static inline CK_RV xk_WrapKeyAuthenticated(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
	CK_OBJECT_HANDLE wrappingKey, CK_OBJECT_HANDLE key, CK_BYTE_PTR aad, CK_ULONG aadLen,
	CK_BYTE_PTR wrapped, CK_ULONG_PTR wrappedLen) {
	return fl->C_WrapKeyAuthenticated(session, mech, wrappingKey, key, aad, aadLen, wrapped, wrappedLen);
}

static inline CK_RV xk_UnwrapKeyAuthenticated(CK_FUNCTION_LIST_3_2_PTR fl, CK_SESSION_HANDLE session, CK_MECHANISM_PTR mech,
	CK_OBJECT_HANDLE unwrappingKey, CK_BYTE_PTR wrapped, CK_ULONG wrappedLen,
	CK_ATTRIBUTE_PTR tmpl, CK_ULONG count, CK_BYTE_PTR aad, CK_ULONG aadLen,
	CK_OBJECT_HANDLE_PTR key) {
	return fl->C_UnwrapKeyAuthenticated(session, mech, unwrappingKey, wrapped, wrappedLen, tmpl, count, aad, aadLen, key);
}

/* ---- struct field accessors ----
 *
 * Go cannot index a C array through an opaque pointer, so element writes and
 * reads for the two array-of-struct templates go through these. */

static inline void xk_attr_set(CK_ATTRIBUTE_PTR base, CK_ULONG i, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR value, CK_ULONG len) {
	base[i].type = type;
	base[i].pValue = value;
	base[i].ulValueLen = len;
}
static inline CK_ULONG xk_attr_len(CK_ATTRIBUTE_PTR base, CK_ULONG i) { return base[i].ulValueLen; }

static inline void xk_prf_set(CK_PRF_DATA_PARAM_PTR base, CK_ULONG i, CK_PRF_DATA_TYPE type, CK_VOID_PTR value, CK_ULONG len) {
	base[i].type = type;
	base[i].pValue = value;
	base[i].ulValueLen = len;
}

#endif /* XKMS_TEST_XKABI_H */
