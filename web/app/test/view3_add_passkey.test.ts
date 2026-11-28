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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";

const webAuthnAddCredentialBegin = vi.fn();
const webAuthnRegisterFinish = vi.fn();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ auth: { webAuthnAddCredentialBegin, webAuthnRegisterFinish } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

// vi.mock factories are hoisted above the imports, so the bridge mocks are too.
const { parsedOptions, encoded, parseCreationOptions, encodeAttestationResponse } = vi.hoisted(() => {
  const parsedOptions = { challenge: new Uint8Array([1, 2, 3]) };
  const encoded = { id: "cred-1", rawId: "cred-1", type: "public-key", response: {} };
  return {
    parsedOptions,
    encoded,
    parseCreationOptions: vi.fn((_raw: unknown) => parsedOptions),
    encodeAttestationResponse: vi.fn((_cred: unknown) => encoded),
  };
});

vi.mock("@go-xkms/sdk", async (importOriginal) => {
  const real = await importOriginal<Record<string, unknown>>();
  return { ...real, parseCreationOptions, encodeAttestationResponse };
});

import AddPasskeyView from "../src/views/AddPasskeyView.svelte";

const rawOptions = { publicKey: { challenge: "AQID" } };
const credential = { id: "cred-1", type: "public-key" };
const create = vi.fn();

function installCredentials(): void {
  Object.defineProperty(navigator, "credentials", {
    value: { create },
    configurable: true,
    writable: true,
  });
}

function removeCredentials(): void {
  Object.defineProperty(navigator, "credentials", {
    value: undefined,
    configurable: true,
    writable: true,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  installCredentials();
});

afterEach(() => {
  // Leave navigator as jsdom provides it: no credentials container.
  removeCredentials();
});

describe("AddPasskeyView", () => {
  it("runs begin, create with the parsed options, then finish, and toasts success", async () => {
    webAuthnAddCredentialBegin.mockResolvedValue({ options: rawOptions, sessionId: "sess-42" });
    create.mockResolvedValue(credential);
    webAuthnRegisterFinish.mockResolvedValue({ token: "t", user_id: "u1" });

    render(AddPasskeyView);
    await fireEvent.click(screen.getByRole("button", { name: /add passkey/i }));

    await waitFor(() => expect(webAuthnRegisterFinish).toHaveBeenCalledOnce());
    expect(webAuthnAddCredentialBegin).toHaveBeenCalledOnce();
    expect(parseCreationOptions).toHaveBeenCalledWith(rawOptions);
    expect(create).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledWith({ publicKey: parsedOptions });
    expect(encodeAttestationResponse).toHaveBeenCalledWith(credential);
    expect(webAuthnRegisterFinish).toHaveBeenCalledWith("sess-42", encoded);
    await waitFor(() => expect(toasts.some((t) => t.kind === "success")).toBe(true));
  });

  it("never renders or toasts the returned token or refresh token", async () => {
    webAuthnAddCredentialBegin.mockResolvedValue({ options: rawOptions, sessionId: "sess-42" });
    create.mockResolvedValue(credential);
    webAuthnRegisterFinish.mockResolvedValue({
      token: "tok-SECRET-123",
      refresh_token: "refresh-SECRET-456",
      user_id: "u1",
    });

    render(AddPasskeyView);
    await fireEvent.click(screen.getByRole("button", { name: /add passkey/i }));

    await waitFor(() => expect(toasts.length).toBeGreaterThan(0));
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("tok-SECRET-123");
    expect(text).not.toContain("refresh-SECRET-456");
    for (const t of toasts) {
      expect(t.message).not.toContain("tok-SECRET-123");
      expect(t.message).not.toContain("refresh-SECRET-456");
    }
  });

  it("reports a cancelled ceremony and does not call finish", async () => {
    webAuthnAddCredentialBegin.mockResolvedValue({ options: rawOptions, sessionId: "sess-42" });
    create.mockRejectedValue(new DOMException("The operation was aborted.", "NotAllowedError"));

    render(AddPasskeyView);
    await fireEvent.click(screen.getByRole("button", { name: /add passkey/i }));

    expect(await screen.findByText(/Passkey creation was cancelled/)).toBeInTheDocument();
    expect(webAuthnRegisterFinish).not.toHaveBeenCalled();
  });

  it("disables the button and explains when the browser has no passkey support", () => {
    removeCredentials();

    render(AddPasskeyView);

    expect(screen.getByRole("button", { name: /add passkey/i })).toBeDisabled();
    expect(screen.getByText(/browser does not support passkeys/i)).toBeInTheDocument();
  });

  it("shows the error when begin is rejected", async () => {
    webAuthnAddCredentialBegin.mockRejectedValue(new Error("webauthn not configured"));

    render(AddPasskeyView);
    await fireEvent.click(screen.getByRole("button", { name: /add passkey/i }));

    expect(await screen.findByText("webauthn not configured")).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
    expect(webAuthnRegisterFinish).not.toHaveBeenCalled();
  });

  it("shows the error when finish is rejected", async () => {
    webAuthnAddCredentialBegin.mockResolvedValue({ options: rawOptions, sessionId: "sess-42" });
    create.mockResolvedValue(credential);
    webAuthnRegisterFinish.mockRejectedValue(new Error("attestation rejected"));

    render(AddPasskeyView);
    await fireEvent.click(screen.getByRole("button", { name: /add passkey/i }));

    expect(await screen.findByText("attestation rejected")).toBeInTheDocument();
    expect(toasts.some((t) => t.kind === "success")).toBe(false);
  });
});
