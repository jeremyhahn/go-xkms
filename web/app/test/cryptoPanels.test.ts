// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { KeyInfo } from "@go-xkms/sdk";

// One fake SDK shared by every panel under test. Each op records the request
// it received so the assertions can check the wire body, which is where the
// interesting bugs live (a dropped nonce or a mis-encoded plaintext looks
// identical in the UI and fails only at the backend).
const encrypt = vi.fn();
const encryptAsym = vi.fn();
const decrypt = vi.fn();
const wrapById = vi.fn();
const unwrapById = vi.fn();
const deriveECDH = vi.fn();
const backendsList = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    keys: { encrypt, encryptAsym, decrypt, wrapById, unwrapById, deriveECDH },
    backends: { list: backendsList },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import EncryptPanel from "../src/components/keys/EncryptPanel.svelte";
import DecryptPanel from "../src/components/keys/DecryptPanel.svelte";
import WrapPanel from "../src/components/keys/WrapPanel.svelte";
import DerivePanel from "../src/components/keys/DerivePanel.svelte";

const aesKey: KeyInfo = {
  key_id: "vault-aes",
  key_type: "symmetric",
  algorithm: "aes-256-gcm",
  backend: "software",
};

const rsaKey: KeyInfo = {
  key_id: "vault-rsa",
  key_type: "rsa",
  algorithm: "rsa-2048",
  backend: "tpm2",
};

const ecKey: KeyInfo = {
  key_id: "vault-ec",
  key_type: "ecdsa",
  algorithm: "ecdsa-p256",
  backend: "pkcs11",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  backendsList.mockResolvedValue({ backends: [], pagination: {} });
});

describe("EncryptPanel", () => {
  it("routes a symmetric key to encrypt and sends UTF-8 plaintext as base64", async () => {
    encrypt.mockResolvedValue({ ciphertext: "Y3Q=", nonce: "bm9uY2U=", tag: "dGFn" });
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "café" } });
    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    await waitFor(() => expect(encrypt).toHaveBeenCalledOnce());
    const [id, req] = encrypt.mock.calls[0]!;
    expect(id).toBe("vault-aes");
    expect(req.backend).toBe("software");
    // "café" is 5 UTF-8 bytes; the Latin-1 btoa idiom would produce 4.
    expect(req.plaintext).toBe("Y2Fmw6k=");
    expect(encryptAsym).not.toHaveBeenCalled();
  });

  it("routes an asymmetric key to encrypt-asym instead", async () => {
    encryptAsym.mockResolvedValue({ ciphertext: "Y3Q=" });
    render(EncryptPanel, { props: { keyInfo: rsaKey } });

    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "hi" } });
    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    await waitFor(() => expect(encryptAsym).toHaveBeenCalledOnce());
    expect(encrypt).not.toHaveBeenCalled();
    expect(encryptAsym.mock.calls[0]![1].hash).toBe("sha256");
  });

  it("omits an empty nonce so the server generates one", async () => {
    encrypt.mockResolvedValue({ ciphertext: "Y3Q=", nonce: "bm9uY2U=", tag: "dGFn" });
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    await waitFor(() => expect(encrypt).toHaveBeenCalledOnce());
    // A present-but-empty nonce would be a fixed all-zero IV at the backend.
    expect(encrypt.mock.calls[0]![1]).not.toHaveProperty("nonce");
  });

  it("refuses to send malformed base64 rather than letting the server 400", async () => {
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("tab", { name: "Base64" }));
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "not base64!!" } });
    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    expect(await screen.findByText("Plaintext is not valid base64.")).toBeInTheDocument();
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("surfaces a server error instead of showing a partial result", async () => {
    encrypt.mockRejectedValue(new Error("backend does not support aes-gcm"));
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    expect(await screen.findByText("backend does not support aes-gcm")).toBeInTheDocument();
  });
});

describe("DecryptPanel", () => {
  it("sends ciphertext, nonce and tag together", async () => {
    decrypt.mockResolvedValue({ plaintext: "aGk=" });
    render(DecryptPanel, { props: { keyInfo: aesKey } });

    const boxes = screen.getAllByRole("textbox");
    await fireEvent.input(boxes[0]!, { target: { value: "Y3Q=" } });
    await fireEvent.input(boxes[1]!, { target: { value: "bm9uY2U=" } });
    await fireEvent.input(boxes[2]!, { target: { value: "dGFn" } });
    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));

    await waitFor(() => expect(decrypt).toHaveBeenCalledOnce());
    const [, req] = decrypt.mock.calls[0]!;
    expect(req).toMatchObject({ ciphertext: "Y3Q=", nonce: "bm9uY2U=", tag: "dGFn" });
  });

  it("requires ciphertext before issuing a request", async () => {
    render(DecryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));

    expect(await screen.findByText("Ciphertext is required.")).toBeInTheDocument();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("reports an authentication failure rather than showing plaintext", async () => {
    decrypt.mockRejectedValue(new Error("cipher: message authentication failed"));
    render(DecryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "Y3Q=" } });
    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));

    expect(
      await screen.findByText("cipher: message authentication failed"),
    ).toBeInTheDocument();
  });
});

describe("WrapPanel", () => {
  const allKeys = [aesKey, rsaKey, ecKey];

  it("wraps a chosen target under the open key and never sends material", async () => {
    wrapById.mockResolvedValue({ wrapped_key: "d3JhcHBlZA==", algorithm: "RSAES_OAEP_SHA_256" });
    render(WrapPanel, {
      props: { keyInfo: rsaKey, allKeys, onChanged: () => {} },
    });

    await fireEvent.change(screen.getAllByRole("combobox")[0]!, { target: { value: "vault-aes" } });
    await fireEvent.click(screen.getByRole("button", { name: "Wrap key" }));

    await waitFor(() => expect(wrapById).toHaveBeenCalledOnce());
    const req = wrapById.mock.calls[0]![0];
    expect(req).toMatchObject({
      wrapping_key_id: "vault-rsa",
      wrapping_key_backend: "tpm2",
      target_key_id: "vault-aes",
      target_key_backend: "software",
    });
    // The point of wrap-by-id: the client never holds the target's material.
    expect(req).not.toHaveProperty("target_key_material");
  });

  it("excludes the wrapping key itself from the target list", () => {
    render(WrapPanel, {
      props: { keyInfo: rsaKey, allKeys, onChanged: () => {} },
    });

    const options = Array.from(
      (screen.getAllByRole("combobox")[0] as HTMLSelectElement).options,
    ).map((o) => o.value);
    expect(options).not.toContain("vault-rsa");
    expect(options).toContain("vault-aes");
  });

  it("refuses an unwrap whose blob is not base64", async () => {
    render(WrapPanel, {
      props: { keyInfo: rsaKey, allKeys, onChanged: () => {} },
    });

    await fireEvent.click(screen.getByRole("tab", { name: "Unwrap" }));
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, {
      target: { value: "not base64!!" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Unwrap into new key" }));

    expect(await screen.findByText("Wrapped key must be valid base64.")).toBeInTheDocument();
    expect(unwrapById).not.toHaveBeenCalled();
  });

  it("notifies the caller after an unwrap creates a key", async () => {
    unwrapById.mockResolvedValue({ key_id: "new-key", backend: "tpm2", success: true });
    const onChanged = vi.fn();
    render(WrapPanel, { props: { keyInfo: rsaKey, allKeys, onChanged } });

    await fireEvent.click(screen.getByRole("tab", { name: "Unwrap" }));
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "d3JhcHBlZA==" } });
    const textInputs = screen.getAllByRole("textbox");
    await fireEvent.input(textInputs[textInputs.length - 2]!, { target: { value: "new-key" } });
    await fireEvent.click(screen.getByRole("button", { name: "Unwrap into new key" }));

    await waitFor(() => expect(unwrapById).toHaveBeenCalledOnce());
    expect(onChanged).toHaveBeenCalled();
  });
});

describe("DerivePanel", () => {
  it("strips PEM armor so an operator can paste what the console shows", async () => {
    deriveECDH.mockResolvedValue({ derived_key: "ZGVyaXZlZA==" });
    render(DerivePanel, { props: { keyInfo: ecKey } });

    const pem = "-----BEGIN PUBLIC KEY-----\nAQID\nBAUG\n-----END PUBLIC KEY-----";
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: pem } });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    await waitFor(() => expect(deriveECDH).toHaveBeenCalledOnce());
    expect(deriveECDH.mock.calls[0]![0].peer_public_key).toBe("AQIDBAUG");
  });

  it("warns when the key cannot do ECDH at all", () => {
    render(DerivePanel, { props: { keyInfo: rsaKey } });

    expect(screen.getByText(/ECDH requires an EC key/)).toBeInTheDocument();
  });

  it("rejects a peer key that is neither PEM nor base64", async () => {
    render(DerivePanel, { props: { keyInfo: ecKey } });

    await fireEvent.input(screen.getAllByRole("textbox")[0]!, {
      target: { value: "definitely not a key!!" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    expect(
      await screen.findByText("Peer public key must be PEM or base64 DER."),
    ).toBeInTheDocument();
    expect(deriveECDH).not.toHaveBeenCalled();
  });
});
