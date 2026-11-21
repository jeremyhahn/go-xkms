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

// A software-backend result (AES-GCM): ciphertext, nonce, tag, key version.
const sealed: SealResponse = {
  backend: "software",
  ciphertext: textToB64("cipher"),
  nonce: textToB64("nonce"),
  tag: textToB64("tag"),
  metadata: { pcr: textToB64("7") },
  key_id: "k1",
  key_version: 2,
};

// What pkg/api/rest SealResponse marshals for a TPM2 seal: Ciphertext has
// no omitempty and is nil, so it arrives as null; the sealed object travels
// in tpm_public/tpm_private, and there is no key version.
const tpmSealed = {
  backend: "tpm2",
  ciphertext: null,
  tpm_public: textToB64("tpm-public-area"),
  tpm_private: textToB64("tpm-private-area"),
  metadata: { "tpm:creation_ticket": textToB64("ticket") },
  key_id: "sealed-1",
} as unknown as SealResponse;

// An envelope-sealing backend's result carries its wrapped DEK.
const envelopeSealed = {
  backend: "awskms",
  ciphertext: textToB64("cipher"),
  nonce: textToB64("nonce"),
  wrapped_dek: textToB64("wrapped-dek"),
  key_id: "arn:aws:kms:k1",
  key_version: 1,
} as unknown as SealResponse;

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
    seal.mockResolvedValue(tpmSealed);
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
    expect(JSON.parse(result.textContent ?? "")).toEqual(tpmSealed);
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
      backend: "software",
      ciphertext: sealed.ciphertext,
      nonce: sealed.nonce,
      tag: sealed.tag,
      metadata: sealed.metadata,
      key_id: "k1",
      key_version: 2,
    });
    expect((await screen.findByLabelText("Plaintext")).textContent).toBe("hello");
  });

  it("unseals a real TPM2 seal result with its sealed object and the password", async () => {
    unseal.mockResolvedValue({ plaintext: textToB64("hello") });
    render(SealView);
    await screen.findByRole("option", { name: "tpm2" });

    await fireEvent.input(screen.getByLabelText("Seal result JSON"), {
      target: { value: JSON.stringify(tpmSealed) },
    });
    await fireEvent.input(screen.getByLabelText("Unseal password"), { target: { value: "s3cret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() => expect(unseal).toHaveBeenCalledOnce());
    expect(unseal.mock.calls[0]![0]).toEqual({
      backend: "tpm2",
      tpm_public: textToB64("tpm-public-area"),
      tpm_private: textToB64("tpm-private-area"),
      metadata: { "tpm:creation_ticket": textToB64("ticket") },
      key_id: "sealed-1",
      password: "s3cret",
    });
    expect((await screen.findByLabelText("Plaintext")).textContent).toBe("hello");
  });

  it("unseals an envelope seal result with its wrapped DEK", async () => {
    unseal.mockResolvedValue({ plaintext: textToB64("hello") });
    render(SealView);
    await screen.findByRole("option", { name: "tpm2" });

    await fireEvent.input(screen.getByLabelText("Seal result JSON"), {
      target: { value: JSON.stringify(envelopeSealed) },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() => expect(unseal).toHaveBeenCalledOnce());
    expect(unseal.mock.calls[0]![0]).toEqual({
      backend: "awskms",
      ciphertext: textToB64("cipher"),
      nonce: textToB64("nonce"),
      wrapped_dek: textToB64("wrapped-dek"),
      key_id: "arn:aws:kms:k1",
      key_version: 1,
    });
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

describe("SealView without the backend list", () => {
  it("keeps Unseal usable when backends.list() is refused", async () => {
    backendsList.mockRejectedValue(new Error("permission denied"));
    unseal.mockResolvedValue({ plaintext: "aGk=" } as UnsealResponse);
    render(SealView);

    expect(await screen.findByText("permission denied")).toBeInTheDocument();
    const json = JSON.stringify({ backend: "software", ciphertext: "AAEC", nonce: "AA==" });
    await fireEvent.input(screen.getByLabelText("Seal result JSON"), { target: { value: json } });
    await fireEvent.click(screen.getByRole("button", { name: "Unseal" }));

    await waitFor(() => expect(unseal).toHaveBeenCalledOnce());
    expect(await screen.findByLabelText("Plaintext")).toHaveTextContent("hi");
  });

  it("lets a caller with keys:encrypt type a backend and seal when both reads are refused", async () => {
    backendsList.mockRejectedValue(new Error("permission denied: backends:list"));
    capability.mockRejectedValue(new Error("permission denied: keys:get"));
    seal.mockResolvedValue(sealed);
    render(SealView);

    expect(await screen.findByText("permission denied: backends:list")).toBeInTheDocument();
    const field = screen.getByLabelText("Backend") as HTMLInputElement;
    expect(field.tagName).toBe("INPUT");
    await fireEvent.input(field, { target: { value: "software" } });
    await fireEvent.change(field, { target: { value: "software" } });
    await waitFor(() => expect(capability).toHaveBeenCalledWith("software"));
    expect(await screen.findByText(/Could not check whether backend software can seal/)).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Text to seal"), { target: { value: "hello" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Seal" })).toBeEnabled());
    await fireEvent.click(screen.getByRole("button", { name: "Seal" }));

    await waitFor(() => expect(seal).toHaveBeenCalledOnce());
    expect(seal.mock.calls[0]![0]).toEqual({ backend: "software", data: textToB64("hello") });
  });

  it("still refuses a typed backend the capability read says cannot seal", async () => {
    backendsList.mockRejectedValue(new Error("permission denied"));
    capability.mockResolvedValue({ can_seal: false, backend: "software" });
    render(SealView);

    const field = await screen.findByLabelText("Backend");
    await fireEvent.input(field, { target: { value: "software" } });
    await fireEvent.change(field, { target: { value: "software" } });
    await fireEvent.input(screen.getByLabelText("Text to seal"), { target: { value: "hello" } });
    expect(await screen.findByText("Backend software cannot seal.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Seal" })).toBeDisabled();
  });
});

describe("SealView without the capability read", () => {
  it("seals on a listed backend when the capability read (keys:get) is refused", async () => {
    capability.mockRejectedValue(new Error("permission denied: keys:get"));
    seal.mockResolvedValue(tpmSealed);
    render(SealView);

    await chooseBackend("tpm2");
    await waitFor(() => expect(capability).toHaveBeenCalledWith("tpm2"));
    expect(await screen.findByText(/Could not check whether backend tpm2 can seal/)).toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText("Text to seal"), { target: { value: "hello" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Seal" })).toBeEnabled());
    await fireEvent.click(screen.getByRole("button", { name: "Seal" }));

    await waitFor(() => expect(seal).toHaveBeenCalledOnce());
    expect(seal.mock.calls[0]![0]).toEqual({ backend: "tpm2", data: textToB64("hello") });
  });

  it("keeps Seal disabled while the capability read is in flight", async () => {
    capability.mockReturnValue(new Promise<CanSealResponse>(() => {}));
    render(SealView);

    await chooseBackend("tpm2");
    await fireEvent.input(screen.getByLabelText("Text to seal"), { target: { value: "hello" } });
    expect(screen.getByRole("button", { name: "Seal" })).toBeDisabled();
  });
});
