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
import type { SSHKeyListResponse, SSHSignRequest, SSHSignResponse } from "@go-xkms/sdk";

const listKeys = vi.fn<(scope?: string, owner?: string) => Promise<SSHKeyListResponse>>();
const sign = vi.fn<(scope: string, owner: string, name: string, req: SSHSignRequest) => Promise<SSHSignResponse>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ ssh: { listKeys, sign } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SshSignView from "../src/views/SshSignView.svelte";

const deployKey = {
  scope: "user",
  owner: "alice",
  name: "deploy",
  algorithm: "ssh-ed25519",
  public_key: "ssh-ed25519 AAAA",
  fingerprint: "SHA256:x",
  created_at: "2026-11-12T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

async function mountWithKey(): Promise<void> {
  listKeys.mockResolvedValue({ items: [deployKey] });
  render(SshSignView);
  await screen.findByRole("option", { name: "user/alice/deploy (ssh-ed25519)" });
}

async function choose(message: string, base64 = false): Promise<void> {
  await fireEvent.change(screen.getByLabelText("Key"), { target: { value: "user/alice/deploy" } });
  if (base64) await fireEvent.click(screen.getByLabelText("Message is base64"));
  await fireEvent.input(screen.getByLabelText("Message"), { target: { value: message } });
}

function signButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Sign" }) as HTMLButtonElement;
}

describe("SshSignView", () => {
  it("lists the caller's SSH keys on mount", async () => {
    await mountWithKey();
    expect(listKeys).toHaveBeenCalledOnce();
    expect(screen.getByRole("option", { name: "user/alice/deploy (ssh-ed25519)" })).toBeInTheDocument();
  });

  it("signs a UTF-8 message and renders format and blob", async () => {
    sign.mockResolvedValue({ format: "ssh-ed25519", blob: "c2ln" });
    await mountWithKey();
    await choose("hello");
    await fireEvent.click(signButton());

    await waitFor(() => expect(sign).toHaveBeenCalledWith("user", "alice", "deploy", { digest: "aGVsbG8=" }));
    expect(await screen.findByText("c2ln")).toBeInTheDocument();
    expect(screen.getByTestId("sign-format")).toHaveTextContent("ssh-ed25519");
    expect(screen.queryByText("Rest")).not.toBeInTheDocument();
  });

  it("sends a base64 message unchanged", async () => {
    sign.mockResolvedValue({ format: "ssh-ed25519", blob: "c2ln" });
    await mountWithKey();
    await choose("aGVsbG8=", true);
    await fireEvent.click(signButton());

    await waitFor(() => expect(sign).toHaveBeenCalledWith("user", "alice", "deploy", { digest: "aGVsbG8=" }));
  });

  it("keeps Sign disabled for an invalid base64 message", async () => {
    await mountWithKey();
    await choose("not base64!", true);
    expect(signButton()).toBeDisabled();
    await fireEvent.click(signButton());
    expect(sign).not.toHaveBeenCalled();
  });

  it("renders a Rest line when the response carries one", async () => {
    sign.mockResolvedValue({ format: "ssh-ed25519", blob: "c2ln", rest: "AAAA" });
    await mountWithKey();
    await choose("hello");
    await fireEvent.click(signButton());

    expect(await screen.findByText("Rest")).toBeInTheDocument();
    expect(screen.getByText("AAAA")).toBeInTheDocument();
  });

  it("keeps Sign disabled with no key or an empty message", async () => {
    await mountWithKey();
    expect(signButton()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Message"), { target: { value: "hello" } });
    expect(signButton()).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Message"), { target: { value: "" } });
    await fireEvent.change(screen.getByLabelText("Key"), { target: { value: "user/alice/deploy" } });
    expect(signButton()).toBeDisabled();
  });

  it("shows an error when listing keys fails", async () => {
    listKeys.mockRejectedValue(new Error("ssh backend down"));
    render(SshSignView);
    expect(await screen.findByText("ssh backend down")).toBeInTheDocument();
  });

  it("shows an error when signing fails", async () => {
    sign.mockRejectedValue(new Error("key not found"));
    await mountWithKey();
    await choose("hello");
    await fireEvent.click(signButton());
    expect(await screen.findByText("key not found")).toBeInTheDocument();
  });
});
