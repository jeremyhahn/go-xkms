// Typed helper for POST /api/v1/keys/{id}/wrapped-data-key (keys:encrypt).
// The data key comes back only in wrapped form; the plaintext data-key route
// (/keys/{id}/data-key) is deliberately not wrapped here and must never be
// called from the browser. Byte fields are standard base64 in JSON
// (pkg/api/transport/types_cryptoutil.go, types.go).
import { getSDKClient } from "$stores/sdkClient.ts";

/** Request body; the key ID comes from the path, the tenant from the session. */
export interface GenerateWrappedDataKeyRequest {
  backend: string;
  /** 16, 24 or 32 bytes; omitted means 32. */
  key_size?: number;
  /** Base64 additional authenticated data. */
  additional_data?: string;
}

/** The wrapped data key, as an encrypt response of the wrapping key. */
export interface EncryptResponse {
  ciphertext: string;
  nonce?: string;
  tag?: string;
  iv?: string;
  gcm_nonce_mode?: string;
  key_version?: number;
}

export interface GenerateWrappedDataKeyResponse {
  wrapped: EncryptResponse;
}

/** Asks key `id` to generate a fresh data key and return it wrapped. */
export function generateWrappedDataKey(
  id: string,
  backend: string,
  keySize?: number,
  aadB64?: string,
): Promise<GenerateWrappedDataKeyResponse> {
  const body: GenerateWrappedDataKeyRequest = { backend };
  if (keySize !== undefined && keySize !== 32) body.key_size = keySize;
  if (aadB64) body.additional_data = aadB64;
  return getSDKClient().http.request<GenerateWrappedDataKeyResponse>(
    "POST",
    `/api/v1/keys/${encodeURIComponent(id)}/wrapped-data-key`,
    { body },
  );
}
