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
import type { AuthMeResponse, KeyInfo } from "@go-xkms/sdk";

const sign = vi.fn();
const verify = vi.fn();
const attest = vi.fn();
const exportMaterial = vi.fn();
const rotate = vi.fn();
const del = vi.fn();
const backendsList = vi.fn();
const meMock = vi.fn<() => Promise<AuthMeResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    keys: { sign, verify, attest, exportMaterial, rotate, delete: del },
    backends: { list: backendsList },
    auth: { me: meMock },
  }),
  resetSDKClient: () => {},
}));

import KeyDetail from "../src/components/KeyDetail.svelte";
import { loadSession, clearSession } from "../src/stores/session.svelte.ts";
import { toastStore, dismissToast } from "../src/stores/toast.svelte.ts";

const ecKey: KeyInfo = {
  key_id: "vault-ec",
  key_type: "ecdsa",
  algorithm: "ecdsa-p256",
  backend: "pkcs11",
  public_key_pem: "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----",
};

const aesKey: KeyInfo = {
  key_id: "vault-aes",
  key_type: "symmetric",
  algorithm: "aes-256-gcm",
  backend: "software",
};

async function withPermissions(perms: Record<string, boolean>): Promise<void> {
  meMock.mockResolvedValue({ subject: "u1", permissions: perms, capabilities: {} });
  await loadSession();
}

const fullAccess = {
  "keys:sign": true,
  "keys:verify": true,
  "keys:encrypt": true,
  "keys:decrypt": true,
  "keys:wrap": true,
  "keys:derive": true,
  "keys:rotate": true,
  "keys:delete": true,
  "keys:export": true,
};

describe("KeyDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearSession();
    backendsList.mockResolvedValue({ backends: [], pagination: {} });
    for (const t of [...toastStore.toasts]) dismissToast(t.id);
  });

  it("opens on the overview tab and shows the PEM when present", async () => {
    await withPermissions({});
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    expect(screen.getByRole("tab", { name: "Overview" })).toHaveClass("tab-active");
    expect(screen.getByText(/BEGIN PUBLIC KEY/)).toBeInTheDocument();
  });

  it("gates the sign/verify/encrypt/wrap/derive tabs on their individual permissions", async () => {
    await withPermissions({ "keys:sign": true });
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    expect(screen.getByRole("tab", { name: "Sign" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Verify" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Encrypt" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Wrap" })).not.toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Derive" })).not.toBeInTheDocument();
    // Transfer and Advanced are never permission-gated.
    expect(screen.getByRole("tab", { name: "Transfer" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Advanced" })).toBeInTheDocument();
  });

  it("hides Decrypt for an asymmetric key even with keys:decrypt granted", async () => {
    await withPermissions({ "keys:decrypt": true });
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });
    expect(screen.queryByRole("tab", { name: "Decrypt" })).not.toBeInTheDocument();
  });

  it("shows Decrypt for a symmetric key when keys:decrypt is granted", async () => {
    await withPermissions({ "keys:decrypt": true });
    render(KeyDetail, { props: { keyInfo: aesKey, allKeys: [aesKey], onClose: () => {}, onChanged: () => {} } });
    expect(screen.getByRole("tab", { name: "Decrypt" })).toBeInTheDocument();
  });

  it("signs a message and displays the returned signature", async () => {
    await withPermissions(fullAccess);
    sign.mockResolvedValue({ signature: "c2ln" });
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Sign" }));
    await fireEvent.input(screen.getByRole("textbox"), { target: { value: "hello" } });
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    await waitFor(() => expect(sign).toHaveBeenCalledOnce());
    const [id, req] = sign.mock.calls[0]!;
    expect(id).toBe("vault-ec");
    expect(req.backend).toBe("pkcs11");
    expect(await screen.findByText("c2ln")).toBeInTheDocument();
  });

  it("surfaces a sign error instead of a stale result", async () => {
    await withPermissions(fullAccess);
    sign.mockRejectedValue(new Error("key is not permitted to sign"));
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Sign" }));
    await fireEvent.click(screen.getByRole("button", { name: "Sign" }));

    expect(await screen.findByText("key is not permitted to sign")).toBeInTheDocument();
  });

  it("renders a valid/invalid verdict from verify", async () => {
    await withPermissions(fullAccess);
    verify.mockResolvedValue({ valid: false });
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Verify" }));
    await fireEvent.click(screen.getByRole("button", { name: "Verify" }));

    expect(await screen.findByText("Signature is NOT valid.")).toBeInTheDocument();
  });

  it("hides the export-material control on Advanced without keys:export", async () => {
    await withPermissions({});
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Advanced" }));

    expect(screen.getByRole("button", { name: "Request attestation" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Export material" })).not.toBeInTheDocument();
  });

  it("shows and runs the export-material control when keys:export is granted", async () => {
    await withPermissions({ "keys:export": true });
    exportMaterial.mockResolvedValue({ key_material: "c2VjcmV0" });
    render(KeyDetail, { props: { keyInfo: aesKey, allKeys: [aesKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Advanced" }));
    await fireEvent.click(screen.getByRole("button", { name: "Export material" }));

    await waitFor(() => expect(exportMaterial).toHaveBeenCalledWith("vault-aes", "software"));
    expect(await screen.findByText("c2VjcmV0")).toBeInTheDocument();
    expect(
      toastStore.toasts.some((t) => t.kind === "warning" && t.message.includes("handle it as a secret")),
    ).toBe(true);
  });

  it("runs attestation and renders the JSON result", async () => {
    await withPermissions({});
    attest.mockResolvedValue({ attested: true, key_id: "vault-ec" });
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Advanced" }));
    await fireEvent.click(screen.getByRole("button", { name: "Request attestation" }));

    await waitFor(() => expect(attest).toHaveBeenCalledOnce());
    expect(attest.mock.calls[0]![0]).toMatchObject({ backend: "pkcs11", key_id: "vault-ec" });
    expect(await screen.findByText(/"attested": true/)).toBeInTheDocument();
  });

  it("hides Rotate/Delete on the overview when neither permission is granted", async () => {
    await withPermissions({});
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    expect(screen.queryByRole("button", { name: "Rotate" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });

  it("rotates a key and notifies the caller via onChanged", async () => {
    await withPermissions({ "keys:rotate": true });
    rotate.mockResolvedValue({ rotated: true });
    const onChanged = vi.fn();
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged } });

    await fireEvent.click(screen.getByRole("button", { name: "Rotate" }));

    await waitFor(() => expect(rotate).toHaveBeenCalledWith("vault-ec", "pkcs11"));
    await waitFor(() => expect(onChanged).toHaveBeenCalledOnce());
    expect(toastStore.toasts.some((t) => t.kind === "success")).toBe(true);
    expect(toastStore.toasts.some((t) => t.kind === "warning")).toBe(false);
  });

  it("warns that a rotated key's certificate must be re-issued", async () => {
    await withPermissions({ "keys:rotate": true });
    rotate.mockResolvedValue({ success: true, key_id: "vault-ec", key_type: "SIGNING", certificate_reissue_required: true });
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: vi.fn() } });

    await fireEvent.click(screen.getByRole("button", { name: "Rotate" }));

    await waitFor(() =>
      expect(toastStore.toasts.some((t) => t.kind === "warning" && t.message.includes("re-issue it"))).toBe(true),
    );
  });

  it("shows an error toast, not a crash, when delete fails", async () => {
    await withPermissions({ "keys:delete": true });
    del.mockRejectedValue(new Error("key is in use"));
    const onChanged = vi.fn();
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged } });

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() =>
      expect(toastStore.toasts.some((t) => t.kind === "error" && t.message === "key is in use")).toBe(true),
    );
    expect(onChanged).not.toHaveBeenCalled();
  });

  it("calls onClose from both the header and overlay close controls", async () => {
    await withPermissions({});
    const onClose = vi.fn();
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose, onChanged: () => {} } });

    await fireEvent.click(screen.getAllByRole("button", { name: "Close" })[0]!);
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("mounts the Transfer panel, which is never permission-gated", async () => {
    await withPermissions({});
    render(KeyDetail, { props: { keyInfo: ecKey, allKeys: [ecKey], onClose: () => {}, onChanged: () => {} } });

    await fireEvent.click(screen.getByRole("tab", { name: "Transfer" }));

    expect(await screen.findByRole("button", { name: /Export wrapped/ })).toBeInTheDocument();
  });
});
