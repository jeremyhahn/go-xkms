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
import type {
  CredentialStrategyResponse,
  CredentialSubmitRequest,
  CredentialSubmitResponse,
} from "@go-xkms/sdk";
import { textToB64 } from "../src/lib/b64.ts";

const strategy = vi.fn<() => Promise<CredentialStrategyResponse>>();
const submit = vi.fn<(req: CredentialSubmitRequest) => Promise<CredentialSubmitResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ credentials: { strategy, submit } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import BootCredentialsView from "../src/views/BootCredentialsView.svelte";

const secret = "s3cr3t-unseal-pin";

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function fill(name: string, value: string): Promise<void> {
  await fireEvent.input(screen.getByPlaceholderText("Credential name"), { target: { value: name } });
  await fireEvent.input(screen.getByPlaceholderText("Secret"), { target: { value } });
}

function expectSecretHidden(): void {
  expect(screen.queryByText(secret)).toBeNull();
  expect(screen.queryByText(secret, { exact: false })).toBeNull();
  for (const t of toasts) {
    expect(t.message).not.toContain(secret);
  }
}

describe("BootCredentialsView", () => {
  it("loads the strategy once and shows its name and the auto-unseal badge", async () => {
    strategy.mockResolvedValue({ strategy: "tpm-pin", auto_unseal: true });

    render(BootCredentialsView);

    expect(await screen.findByText("tpm-pin")).toBeInTheDocument();
    expect(screen.getByText("auto-unseal on")).toBeInTheDocument();
    expect(strategy).toHaveBeenCalledOnce();
  });

  it("shows auto-unseal off when the server does not unseal by itself", async () => {
    strategy.mockResolvedValue({ strategy: "passphrase", auto_unseal: false });

    render(BootCredentialsView);

    expect(await screen.findByText("auto-unseal off")).toBeInTheDocument();
  });

  it("submits the name and the base64 secret, toasts the status and clears the secret", async () => {
    strategy.mockResolvedValue({ strategy: "tpm-pin", auto_unseal: false });
    submit.mockResolvedValue({ status: "accepted" });

    render(BootCredentialsView);
    await screen.findByText("tpm-pin");
    await fill("unseal", secret);
    await fireEvent.click(screen.getByRole("button", { name: "Submit" }));

    await waitFor(() => expect(submit).toHaveBeenCalledOnce());
    expect(submit).toHaveBeenCalledWith({ name: "unseal", value: textToB64(secret) });
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: "Boot credential unseal: accepted" }));
    expect((screen.getByPlaceholderText("Secret") as HTMLInputElement).value).toBe("");
    expectSecretHidden();
  });

  it("uses a password input and never renders the secret after a rejected submit", async () => {
    strategy.mockResolvedValue({ strategy: "tpm-pin", auto_unseal: false });
    submit.mockRejectedValue(new Error("credential rejected"));

    render(BootCredentialsView);
    await screen.findByText("tpm-pin");
    const input = screen.getByPlaceholderText("Secret") as HTMLInputElement;
    expect(input.type).toBe("password");

    await fill("unseal", secret);
    await fireEvent.click(screen.getByRole("button", { name: "Submit" }));

    expect(await screen.findByText("credential rejected")).toBeInTheDocument();
    expect(input.value).toBe("");
    expectSecretHidden();
  });

  it("keeps Submit disabled until both name and secret are set", async () => {
    strategy.mockResolvedValue({ strategy: "tpm-pin", auto_unseal: false });

    render(BootCredentialsView);
    await screen.findByText("tpm-pin");
    const button = screen.getByRole("button", { name: "Submit" });
    expect(button).toBeDisabled();

    await fireEvent.input(screen.getByPlaceholderText("Credential name"), { target: { value: "unseal" } });
    expect(button).toBeDisabled();

    await fireEvent.input(screen.getByPlaceholderText("Secret"), { target: { value: secret } });
    expect(button).toBeEnabled();

    await fireEvent.input(screen.getByPlaceholderText("Credential name"), { target: { value: "" } });
    expect(button).toBeDisabled();
  });

  it("shows an info alert when the server has no boot credentials", async () => {
    strategy.mockRejectedValue(new Error("not found"));

    render(BootCredentialsView);

    expect(await screen.findByText("Boot credentials are not available on this server")).toBeInTheDocument();
  });
});
