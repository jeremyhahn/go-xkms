// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type {
  CanSealResponse,
  ListBackendsResponse,
  SealRequest,
  SealResponse,
  UnsealRequest,
  UnsealResponse,
} from "@go-xkms/sdk";
import { textToB64 } from "../src/lib/b64.ts";

const seal = vi.fn<(req: SealRequest) => Promise<SealResponse>>();
const unseal = vi.fn<(req: UnsealRequest) => Promise<UnsealResponse>>();
const capability = vi.fn<(backend?: string) => Promise<CanSealResponse>>();
const backendsList = vi.fn<() => Promise<ListBackendsResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ seal: { seal, unseal, capability }, backends: { list: backendsList } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SealView from "../src/views/SealView.svelte";

const sealed: SealResponse = {
  backend: "tpm2",
  ciphertext: textToB64("cipher"),
  nonce: textToB64("nonce"),
  tag: textToB64("tag"),
  metadata: { pcr: textToB64("7") },
  key_id: "k1",
  key_version: 2,
};

function backends(): ListBackendsResponse {
  return {
    backends: [
      { id: "tpm2", type: "tpm2", hardware_backed: true },
      { id: "software", type: "software", hardware_backed: false },
    ],
  } as unknown as ListBackendsResponse;
}

async function chooseBackend(id: string): Promise<void> {
  const select = await screen.findByLabelText("Backend");
  await screen.findByRole("option", { name: id });
  await fireEvent.change(select, { target: { value: id } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  backendsList.mockResolvedValue(backends());
  capability.mockResolvedValue({ can_seal: true, backend: "tpm2" });
});

describe("SealView", () => {
  it("lists the backends and checks the chosen backend's capability", async () => {
    capability.mockResolvedValue({ can_seal: false, backend: "software" });
    render(SealView);

    expect(await screen.findByRole("option", { name: "tpm2" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "software" })).toBeInTheDocument();

    await chooseBackend("software");
    await waitFor(() => expect(capability).toHaveBeenCalledWith("software"));
    expect(await screen.findByText("Backend software cannot seal.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Seal" })).toBeDisabled();
  });

  it("seals with only the filled fields and shows the result JSON", async () => {
    seal.mockResolvedValue(sealed);
    render(SealView);

    await chooseBackend("tpm2");
    await waitFor(() => expect(capability).toHaveBeenCalledWith("tpm2"));
    await fireEvent.input(screen.getByLabelText("Text to seal"), { target: { value: "hello" } });
    await fireEvent.input(screen.getByLabelText("TPM policy"), { target: { value: "platform" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Seal" })).toBeEnabled());
    await fireEvent.click(screen.getByRole("button", { name: "Seal" }));

    await waitFor(() => expect(seal).toHaveBeenCalledOnce());
    const req = seal.mock.calls[0]![0];
    expect(req).toEqual({ backend: "tpm2", data: textToB64("hello"), tpm_policy: "platform" });
    expect(Object.keys(req).sort()).toEqual(["backend", "data", "tpm_policy"]);

    const result = await screen.findByLabelText("Seal result");
    expect(JSON.parse(result.textContent ?? "")).toEqual(sealed);
    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
  });

  it("unseals from the seal result JSON and shows the plaintext", async () => {
    unseal.mockResolvedValue({ plaintext: textToB64("hello") });
    render(SealView);
    await screen.findByRole("option", { name: "tpm2" });

    await fireEvent.input(screen.getByLabelText("Seal result JSON"), {
      target: { value: JSON.stringify(sealed) },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() => expect(unseal).toHaveBeenCalledOnce());
    const req = unseal.mock.calls[0]![0];
    expect(req).toEqual({
      backend: "tpm2",
      ciphertext: sealed.ciphertext,
      nonce: sealed.nonce,
      tag: sealed.tag,
      metadata: sealed.metadata,
      key_id: "k1",
      key_version: 2,
    });
    expect((await screen.findByLabelText("Plaintext")).textContent).toBe("hello");
  });

  it("rejects invalid JSON and a non-base64 ciphertext inline without a call", async () => {
    render(SealView);
    await screen.findByRole("option", { name: "tpm2" });
    const box = screen.getByLabelText("Seal result JSON");

    await fireEvent.input(box, { target: { value: "{not json" } });
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));
    expect(await screen.findByText("Invalid seal result JSON.")).toBeInTheDocument();

    await fireEvent.input(box, { target: { value: JSON.stringify({ ...sealed, ciphertext: "%%%" }) } });
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));
    expect(await screen.findByText("Ciphertext is not base64.")).toBeInTheDocument();
    expect(unseal).not.toHaveBeenCalled();
  });

  it("toasts a rejected seal and keeps the input", async () => {
    seal.mockRejectedValue(new Error("policy mismatch"));
    render(SealView);

    await chooseBackend("tpm2");
    const text = screen.getByLabelText("Text to seal");
    await fireEvent.input(text, { target: { value: "hello" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Seal" })).toBeEnabled());
    await fireEvent.click(screen.getByRole("button", { name: "Seal" }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "policy mismatch" }));
    expect((text as HTMLTextAreaElement).value).toBe("hello");
    expect(screen.queryByLabelText("Seal result")).toBeNull();
  });

  it("shows an error alert when the backend list fails", async () => {
    backendsList.mockRejectedValue(new Error("backends unavailable"));
    render(SealView);

    expect(await screen.findByText("backends unavailable")).toBeInTheDocument();
  });
});
