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

// Additional branch coverage for the crypto panels beyond test/cryptoPanels.test.ts
// (owned by another agent, not edited here): invalid nonce/AAD/IV validation,
// the base64 and file input modes, copy-to-clipboard, and the AEAD-only field
// visibility toggles that the happy-path suite does not exercise.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { KeyInfo } from "@go-xkms/sdk";

const encrypt = vi.fn();
const decrypt = vi.fn();
const wrapById = vi.fn();
const unwrapById = vi.fn();
const deriveECDH = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    keys: { encrypt, encryptAsym: vi.fn(), decrypt, wrapById, unwrapById, deriveECDH },
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

// jsdom's Blob/File does not implement arrayBuffer() (used by the file-upload
// path); polyfill it so onFile's `await file.arrayBuffer()` resolves instead
// of rejecting. Guarded so it is a no-op wherever a real implementation
// already exists.
if (typeof Blob.prototype.arrayBuffer !== "function") {
  Blob.prototype.arrayBuffer = function (this: Blob): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as ArrayBuffer);
      reader.onerror = () => reject(reader.error);
      reader.readAsArrayBuffer(this);
    });
  };
}

const aesKey: KeyInfo = {
  key_id: "vault-aes",
  key_type: "symmetric",
  algorithm: "aes-256-gcm",
  backend: "software",
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
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
    configurable: true,
  });
});

describe("EncryptPanel extra branches", () => {
  it("rejects a nonce that is not valid base64 before calling the SDK", async () => {
    render(EncryptPanel, { props: { keyInfo: aesKey } });
    await fireEvent.input(screen.getByLabelText(/Nonce \(base64, optional\)/), {
      target: { value: "not base64!!" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    expect(await screen.findByText("Nonce is not valid base64.")).toBeInTheDocument();
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("rejects additional authenticated data that is not valid base64", async () => {
    render(EncryptPanel, { props: { keyInfo: aesKey } });
    await fireEvent.input(screen.getByLabelText(/Additional authenticated data/), {
      target: { value: "not base64!!" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));

    expect(await screen.findByText("Additional authenticated data is not valid base64.")).toBeInTheDocument();
    expect(encrypt).not.toHaveBeenCalled();
  });

  it("generates a 12-byte nonce and sends it verbatim", async () => {
    encrypt.mockResolvedValue({ ciphertext: "Y3Q=", nonce: "bm9uY2U=", tag: "dGFn" });
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("button", { name: "Generate 12 bytes" }));
    const nonceInput = screen.getByLabelText(/Nonce \(base64, optional\)/) as HTMLInputElement;
    expect(nonceInput.value).not.toBe("");

    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));
    await waitFor(() => expect(encrypt).toHaveBeenCalledOnce());
    expect(encrypt.mock.calls[0]![1].nonce).toBe(nonceInput.value);
  });

  it("reads plaintext from an uploaded file rather than the text box", async () => {
    encrypt.mockResolvedValue({ ciphertext: "Y3Q=", nonce: "bm9uY2U=", tag: "dGFn" });
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("tab", { name: "File" }));
    const file = new File([new Uint8Array([1, 2, 3])], "material.bin");
    const fileInput = document.querySelector("input[type='file']") as HTMLInputElement;
    await fireEvent.change(fileInput, { target: { files: [file] } });

    // fileName is set synchronously but plainB64 is only populated once the
    // FileReader-backed arrayBuffer() promise resolves — wait for the final
    // byte count, not just the filename, or the click below can race ahead
    // of the read and submit an empty plaintext.
    await waitFor(() => expect(screen.getByText(/material\.bin · 3 bytes/)).toBeInTheDocument());

    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));
    await waitFor(() => expect(encrypt).toHaveBeenCalledOnce());
    expect(encrypt.mock.calls[0]![1].plaintext).toBe("AQID");
  });

  it("copies a result field to the clipboard", async () => {
    encrypt.mockResolvedValue({ ciphertext: "Y3Q=", nonce: "bm9uY2U=", tag: "dGFn" });
    render(EncryptPanel, { props: { keyInfo: aesKey } });

    await fireEvent.click(screen.getByRole("button", { name: "Encrypt" }));
    await waitFor(() => expect(encrypt).toHaveBeenCalledOnce());

    await fireEvent.click(screen.getAllByRole("button", { name: "Copy" })[0]!);
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledOnce());
    expect(toasts.some((t) => t.kind === "success")).toBe(true);
  });
});

describe("DecryptPanel extra branches", () => {
  it("rejects an invalid-base64 nonce before calling the SDK", async () => {
    render(DecryptPanel, { props: { keyInfo: aesKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "Y3Q=" } });
    await fireEvent.input(screen.getByLabelText("Nonce (base64)"), { target: { value: "not base64!!" } });
    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));

    expect(await screen.findByText("Nonce is not valid base64.")).toBeInTheDocument();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("falls back to the base64 view when the plaintext field itself is not valid base64", async () => {
    decrypt.mockResolvedValue({ plaintext: "not base64!!" });
    render(DecryptPanel, { props: { keyInfo: aesKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "Y3Q=" } });
    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));

    await screen.findByText("not base64!!");
    // decoded is null, so there is no "Show base64"/"Show text" toggle at all.
    expect(screen.queryByRole("button", { name: /Show base64|Show text/ })).not.toBeInTheDocument();
  });

  it("toggles between the decoded text and raw base64 view, and copies the visible form", async () => {
    decrypt.mockResolvedValue({ plaintext: "aGVsbG8=" }); // "hello"
    render(DecryptPanel, { props: { keyInfo: aesKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "Y3Q=" } });
    await fireEvent.click(screen.getByRole("button", { name: "Decrypt" }));

    await screen.findByText("hello");
    await fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("hello"));

    await fireEvent.click(screen.getByRole("button", { name: "Show base64" }));
    expect(screen.getByText("aGVsbG8=")).toBeInTheDocument();
  });
});

describe("WrapPanel extra branches", () => {
  const allKeys = [aesKey, ecKey];

  it("requires a target key before wrapping", async () => {
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    // The wrap button is disabled with no target selected — assert the guard
    // clause directly by re-enabling it is not possible from the DOM, so
    // confirm the disabled state itself, which is the actual protection.
    expect(screen.getByRole("button", { name: "Wrap key" })).toBeDisabled();
  });

  it("reveals AEAD fields (IV/AAD/tag bits) only for the AES_GCM algorithm", async () => {
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    expect(screen.queryByLabelText("IV (base64)")).not.toBeInTheDocument();

    const algoSelects = screen.getAllByRole("combobox");
    await fireEvent.change(algoSelects[1]!, { target: { value: "AES_GCM" } });

    expect(screen.getByLabelText("IV (base64)")).toBeInTheDocument();
  });

  it("rejects an invalid-base64 IV when wrapping under AES_GCM", async () => {
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    const selects = screen.getAllByRole("combobox");
    await fireEvent.change(selects[0]!, { target: { value: "vault-aes" } });
    await fireEvent.change(selects[1]!, { target: { value: "AES_GCM" } });
    await fireEvent.input(screen.getByLabelText("IV (base64)"), { target: { value: "not base64!!" } });

    await fireEvent.click(screen.getByRole("button", { name: "Wrap key" }));

    expect(await screen.findByText("IV is not valid base64.")).toBeInTheDocument();
    expect(wrapById).not.toHaveBeenCalled();
  });

  it("surfaces a server error from wrapById", async () => {
    wrapById.mockRejectedValue(new Error("wrapping key cannot wrap this algorithm"));
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    await fireEvent.change(screen.getAllByRole("combobox")[0]!, { target: { value: "vault-aes" } });
    await fireEvent.click(screen.getByRole("button", { name: "Wrap key" }));

    expect(await screen.findByText("wrapping key cannot wrap this algorithm")).toBeInTheDocument();
  });

  it("copies the wrapped result to the clipboard", async () => {
    wrapById.mockResolvedValue({ wrapped_key: "d3JhcHBlZA==", algorithm: "RSAES_OAEP_SHA_256" });
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    await fireEvent.change(screen.getAllByRole("combobox")[0]!, { target: { value: "vault-aes" } });
    await fireEvent.click(screen.getByRole("button", { name: "Wrap key" }));

    await screen.findByText("d3JhcHBlZA==");
    await fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("d3JhcHBlZA=="));
  });

  it("requires a target key ID before unwrapping, even with a valid blob", async () => {
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    await fireEvent.click(screen.getByRole("tab", { name: "Unwrap" }));
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "d3JhcHBlZA==" } });
    await fireEvent.click(screen.getByRole("button", { name: "Unwrap into new key" }));

    expect(await screen.findByText("A key ID for the unwrapped key is required.")).toBeInTheDocument();
    expect(unwrapById).not.toHaveBeenCalled();
  });

  it("surfaces a server error from unwrapById without dropping the entered blob", async () => {
    unwrapById.mockRejectedValue(new Error("wrong key for this blob"));
    render(WrapPanel, { props: { keyInfo: ecKey, allKeys, onChanged: () => {} } });
    await fireEvent.click(screen.getByRole("tab", { name: "Unwrap" }));
    const textInputs = screen.getAllByRole("textbox");
    await fireEvent.input(textInputs[0]!, { target: { value: "d3JhcHBlZA==" } });
    await fireEvent.input(textInputs[textInputs.length - 2]!, { target: { value: "new-key" } });
    await fireEvent.click(screen.getByRole("button", { name: "Unwrap into new key" }));

    expect(await screen.findByText("wrong key for this blob")).toBeInTheDocument();
    // The blob field is not cleared on failure — only on success.
    expect((screen.getAllByRole("textbox")[0] as HTMLTextAreaElement).value).toBe("d3JhcHBlZA==");
  });
});

describe("DerivePanel extra branches", () => {
  it("rejects a salt that is not valid base64", async () => {
    render(DerivePanel, { props: { keyInfo: ecKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "AQIDBAUG" } });
    await fireEvent.input(screen.getByLabelText(/Salt \(base64, optional\)/), {
      target: { value: "not base64!!" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    expect(await screen.findByText("Salt is not valid base64.")).toBeInTheDocument();
    expect(deriveECDH).not.toHaveBeenCalled();
  });

  it("encodes text info as base64 by default and sends it as kdf_info", async () => {
    deriveECDH.mockResolvedValue({ derived_key: "ZGVyaXZlZA==" });
    render(DerivePanel, { props: { keyInfo: ecKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "AQIDBAUG" } });
    await fireEvent.input(screen.getByLabelText(/Info \/ context/), { target: { value: "purpose-a" } });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    await waitFor(() => expect(deriveECDH).toHaveBeenCalledOnce());
    expect(deriveECDH.mock.calls[0]![0].kdf_info).toBe(btoa("purpose-a"));
  });

  it("switches the info field to raw base64 entry and rejects invalid input", async () => {
    render(DerivePanel, { props: { keyInfo: ecKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "AQIDBAUG" } });
    await fireEvent.click(screen.getByRole("button", { name: "Enter as base64" }));
    await fireEvent.input(screen.getByLabelText(/Info \/ context/), { target: { value: "not base64!!" } });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    expect(await screen.findByText("Info is not valid base64.")).toBeInTheDocument();
    expect(deriveECDH).not.toHaveBeenCalled();
  });

  it("generates a 32-byte salt", async () => {
    render(DerivePanel, { props: { keyInfo: ecKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate 32 bytes" }));
    const saltInput = screen.getByLabelText(/Salt \(base64, optional\)/) as HTMLInputElement;
    expect(saltInput.value).not.toBe("");
  });

  it("surfaces a server error from deriveECDH", async () => {
    deriveECDH.mockRejectedValue(new Error("peer key is not on the curve"));
    render(DerivePanel, { props: { keyInfo: ecKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "AQIDBAUG" } });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    expect(await screen.findByText("peer key is not on the curve")).toBeInTheDocument();
  });

  it("copies the derived key to the clipboard", async () => {
    deriveECDH.mockResolvedValue({ derived_key: "ZGVyaXZlZA==" });
    render(DerivePanel, { props: { keyInfo: ecKey } });
    await fireEvent.input(screen.getAllByRole("textbox")[0]!, { target: { value: "AQIDBAUG" } });
    await fireEvent.click(screen.getByRole("button", { name: "Derive shared key" }));

    await screen.findByText("ZGVyaXZlZA==");
    await fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("ZGVyaXZlZA=="));
  });
});
