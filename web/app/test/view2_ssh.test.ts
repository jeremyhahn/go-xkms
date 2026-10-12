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
//
// NOTE: xkmsd terminates no SSH session on any transport, and this SPA
// deliberately ships no in-browser console (see docs/web-console/architecture.md,
// "What this feature deliberately does not do"). SshView is list /
// generate / delete only, plus a static note pointing operators at the xkey
// client — there is no lazy-imported console and no host/port/user dialog to
// test here.

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { SSHKey, SSHGenerateKeyRequest } from "@go-xkms/sdk";

const listKeys = vi.fn<(scope?: string, owner?: string) => Promise<{ items: SSHKey[] }>>();
const generateKey = vi.fn<(req: SSHGenerateKeyRequest) => Promise<SSHKey>>();
const deleteKey = vi.fn<(scope: string, owner: string, name: string) => Promise<void>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({ ssh: { listKeys, generateKey, deleteKey } }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SshView from "../src/views/SshView.svelte";

function key(over: Partial<SSHKey> = {}): SSHKey {
  return {
    scope: "user",
    owner: "alice",
    name: "laptop",
    algorithm: "ed25519",
    public_key: "ssh-ed25519 AAAA...",
    fingerprint: "SHA256:abcd1234",
    created_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("SshView", () => {
  it("renders keys from the items envelope", async () => {
    listKeys.mockResolvedValue({ items: [key()] });

    render(SshView);

    expect(await screen.findByText("laptop")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getByText("ed25519")).toBeInTheDocument();
    expect(screen.getByText("SHA256:abcd1234")).toBeInTheDocument();
  });

  it("always shows the xkey-client note (xkmsd never opens a session)", async () => {
    listKeys.mockResolvedValue({ items: [key()] });

    render(SshView);
    await screen.findByText("laptop");

    expect(screen.getByText(/it never opens an SSH session itself/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Connect" })).not.toBeInTheDocument();
  });

  it("shows the empty state with no SSH keys", async () => {
    listKeys.mockResolvedValue({ items: [] });

    render(SshView);

    expect(await screen.findByText("No SSH keys.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    listKeys.mockRejectedValue(new Error("ssh backend unavailable"));

    render(SshView);

    expect(await screen.findByText("ssh backend unavailable")).toBeInTheDocument();
  });

  it("generates a key with the form fields and the ed25519 default", async () => {
    listKeys.mockResolvedValue({ items: [] });
    generateKey.mockResolvedValue(key({ name: "new-key" }));

    render(SshView);
    await screen.findByText("No SSH keys.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await fireEvent.input(screen.getByPlaceholderText("Owner"), { target: { value: "bob" } });
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "new-key" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    await waitFor(() => expect(generateKey).toHaveBeenCalledOnce());
    expect(generateKey.mock.calls[0]![0]).toEqual({
      scope: "user",
      owner: "bob",
      name: "new-key",
      algorithm: "ed25519",
    });
  });

  it("surfaces a generate failure inside the dialog", async () => {
    listKeys.mockResolvedValue({ items: [] });
    generateKey.mockRejectedValue(new Error("key name already exists"));

    render(SshView);
    await screen.findByText("No SSH keys.");

    await fireEvent.click(screen.getByRole("button", { name: "+ Generate" }));
    await fireEvent.input(screen.getByPlaceholderText("Owner"), { target: { value: "bob" } });
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "dup" } });
    await fireEvent.click(screen.getByRole("button", { name: "Generate", hidden: true }));

    expect(await screen.findByText("key name already exists")).toBeInTheDocument();
  });

  it("deletes a key using its scope/owner/name triple", async () => {
    listKeys.mockResolvedValueOnce({ items: [key()] });
    deleteKey.mockResolvedValue(undefined);
    listKeys.mockResolvedValueOnce({ items: [] });

    render(SshView);
    await screen.findByText("laptop");

    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));

    await waitFor(() => expect(deleteKey).toHaveBeenCalledWith("user", "alice", "laptop"));
    expect(await screen.findByText("No SSH keys.")).toBeInTheDocument();
  });
});
