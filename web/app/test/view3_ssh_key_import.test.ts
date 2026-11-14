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
import type { SSHImportKeyRequest, SSHKey, SSHPublicKey } from "@go-xkms/sdk";

const importKey = vi.fn<(req: SSHImportKeyRequest) => Promise<SSHKey>>();
const getKey = vi.fn();
const exportPublic = vi.fn<(scope: string, owner: string, name: string) => Promise<SSHPublicKey>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ ssh: { importKey, getKey, exportPublic } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SshKeyImportView from "../src/views/SshKeyImportView.svelte";

// The view never parses the PEM; it only base64-encodes the pasted text, so
// a neutral fixture stands in for a key.
const PEM_BODY = "dGVzdC1maXh0dXJlLW5vdC1hLWtleQSECRETBODY";
const PEM = `-----BEGIN TEST FIXTURE-----\n${PEM_BODY}\n-----END TEST FIXTURE-----\n`;
const PASSPHRASE = "correct-horse-battery";

const imported: SSHKey = {
  scope: "user",
  owner: "alice",
  name: "deploy",
  algorithm: "ssh-ed25519",
  public_key: "ssh-ed25519 AAAAC3Nz deploy",
  fingerprint: "SHA256:abcdef0123456789",
  created_at: "2026-11-12T00:00:00Z",
};

function b64(s: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(s)));
}

async function fillImport(opts: { passphrase?: string } = {}): Promise<void> {
  await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "user" } });
  await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "alice" } });
  await fireEvent.input(screen.getByLabelText("Name"), { target: { value: "deploy" } });
  await fireEvent.input(screen.getByLabelText("Private key (PEM)"), { target: { value: PEM } });
  if (opts.passphrase !== undefined) {
    await fireEvent.input(screen.getByLabelText("Passphrase"), { target: { value: opts.passphrase } });
  }
}

function assertNoSecrets(): void {
  const text = document.body.textContent ?? "";
  expect(text).not.toContain(PEM_BODY);
  expect(text).not.toContain(PASSPHRASE);
  for (const t of toasts) {
    expect(t.message).not.toContain(PEM_BODY);
    expect(t.message).not.toContain(PASSPHRASE);
  }
  expect((screen.getByLabelText("Private key (PEM)") as HTMLTextAreaElement).value).toBe("");
  expect((screen.getByLabelText("Passphrase") as HTMLInputElement).value).toBe("");
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("SshKeyImportView", () => {
  it("keeps Import disabled until scope, owner, name and PEM are set, and calls nothing on mount", async () => {
    render(SshKeyImportView);
    const btn = screen.getByRole("button", { name: "Import" });
    expect(btn).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "user" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "alice" } });
    await fireEvent.input(screen.getByLabelText("Name"), { target: { value: "deploy" } });
    expect(btn).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Private key (PEM)"), { target: { value: PEM } });
    expect(btn).not.toBeDisabled();
    expect(importKey).not.toHaveBeenCalled();
    expect(getKey).not.toHaveBeenCalled();
    expect(exportPublic).not.toHaveBeenCalled();
  });

  it("imports a base64 PEM without a passphrase and shows the algorithm and fingerprint", async () => {
    importKey.mockResolvedValue(imported);
    render(SshKeyImportView);
    await fillImport();
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(importKey).toHaveBeenCalledOnce());
    const req = importKey.mock.calls[0]![0];
    expect(req).toEqual({ scope: "user", owner: "alice", name: "deploy", pem: b64(PEM) });
    expect("passphrase_b64" in req).toBe(false);
    expect(await screen.findByText("ssh-ed25519")).toBeInTheDocument();
    expect(screen.getByText("SHA256:abcdef0123456789")).toBeInTheDocument();
    assertNoSecrets();
  });

  it("sends passphrase_b64 only when a passphrase is given and keeps no secret after success", async () => {
    importKey.mockResolvedValue(imported);
    render(SshKeyImportView);
    await fillImport({ passphrase: PASSPHRASE });
    await fireEvent.input(screen.getByLabelText("Comment"), { target: { value: "ci deploy" } });
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    await waitFor(() => expect(importKey).toHaveBeenCalledOnce());
    expect(importKey.mock.calls[0]![0]).toEqual({
      scope: "user",
      owner: "alice",
      name: "deploy",
      comment: "ci deploy",
      pem: b64(PEM),
      passphrase_b64: b64(PASSPHRASE),
    });
    await screen.findByText("SHA256:abcdef0123456789");
    assertNoSecrets();
  });

  it("shows an import failure in an Alert and keeps no secret after it", async () => {
    importKey.mockRejectedValue(new Error("unsupported key type"));
    render(SshKeyImportView);
    await fillImport({ passphrase: PASSPHRASE });
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));

    const msg = await screen.findByText("unsupported key type");
    expect(msg.closest('[role="alert"]')).not.toBeNull();
    assertNoSecrets();
  });

  it("shows the authorized_keys line of a stored key", async () => {
    exportPublic.mockResolvedValue({
      algorithm: "ssh-ed25519",
      line: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@xkms",
      fingerprint: "SHA256:abcdef0123456789",
    });
    render(SshKeyImportView);
    const btn = screen.getByRole("button", { name: "Show public key" });
    expect(btn).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Lookup scope"), { target: { value: "user" } });
    await fireEvent.input(screen.getByLabelText("Lookup owner"), { target: { value: "alice" } });
    await fireEvent.input(screen.getByLabelText("Lookup name"), { target: { value: "deploy" } });
    await fireEvent.click(btn);

    await waitFor(() => expect(exportPublic).toHaveBeenCalledOnce());
    expect(exportPublic).toHaveBeenCalledWith("user", "alice", "deploy");
    const line = await screen.findByText("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@xkms");
    expect(line.closest("pre")).not.toBeNull();
  });

  it("shows a lookup failure in an Alert", async () => {
    exportPublic.mockRejectedValue(new Error("ssh key not found"));
    render(SshKeyImportView);
    await fireEvent.input(screen.getByLabelText("Lookup scope"), { target: { value: "user" } });
    await fireEvent.input(screen.getByLabelText("Lookup owner"), { target: { value: "alice" } });
    await fireEvent.input(screen.getByLabelText("Lookup name"), { target: { value: "missing" } });
    await fireEvent.click(screen.getByRole("button", { name: "Show public key" }));

    const msg = await screen.findByText("ssh key not found");
    expect(msg.closest('[role="alert"]')).not.toBeNull();
  });
});
