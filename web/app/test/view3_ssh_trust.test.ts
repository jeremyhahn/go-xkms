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
  SSHPinListResponse,
  SSHAuthorizedListResponse,
  SSHAuthorizedEntry,
  SSHAddKnownHostRequest,
  SSHVerifyKnownHostRequest,
  SSHAddAuthorizedKeyRequest,
  SSHVerifyAuthorizedRequest,
} from "@go-xkms/sdk";

const listKnownHosts = vi.fn<(scope?: string, owner?: string) => Promise<SSHPinListResponse>>();
const addKnownHost = vi.fn<(req: SSHAddKnownHostRequest) => Promise<void>>();
const removeKnownHost = vi.fn<(host: string, scope?: string, owner?: string) => Promise<void>>();
const verifyKnownHost = vi.fn<(host: string, req: SSHVerifyKnownHostRequest) => Promise<void>>();
const listAuthorizedKeys = vi.fn<(scope?: string, owner?: string) => Promise<SSHAuthorizedListResponse>>();
const addAuthorizedKey = vi.fn<(req: SSHAddAuthorizedKeyRequest) => Promise<void>>();
const removeAuthorizedKey = vi.fn<(scope: string, owner: string, name: string) => Promise<void>>();
const verifyAuthorizedKey = vi.fn<(req: SSHVerifyAuthorizedRequest) => Promise<SSHAuthorizedEntry>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    ssh: {
      listKnownHosts,
      addKnownHost,
      removeKnownHost,
      verifyKnownHost,
      listAuthorizedKeys,
      addAuthorizedKey,
      removeAuthorizedKey,
      verifyAuthorizedKey,
    },
  }),
  resetSDKClient: () => {},
}));

const toasts: Array<{ kind: string; message: string }> = [];
vi.mock("../src/stores/toast.svelte.ts", () => ({
  showToast: (kind: string, message: string) => {
    toasts.push({ kind, message });
  },
}));

import SshTrustView from "../src/views/SshTrustView.svelte";

const pin = {
  scope: "global",
  owner: "default",
  host: "git.example.com",
  fingerprint: "SHA256:pinnedpinned",
  algorithm: "ssh-ed25519",
  added_at: "2026-11-01T10:00:00Z",
};

const entry: SSHAuthorizedEntry = {
  scope: "global",
  owner: "default",
  name: "deploy",
  line: "ssh-ed25519 AAAAC3Nz deploy@ci",
  options: ["no-pty", "restrict"],
  comment: "deploy@ci",
};

function seed(): void {
  listKnownHosts.mockResolvedValue({ items: [pin] });
  listAuthorizedKeys.mockResolvedValue({ items: [entry] });
}

async function mounted(): Promise<void> {
  render(SshTrustView);
  await screen.findByText("git.example.com");
  await screen.findByText("deploy");
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("SshTrustView", () => {
  it("lists known hosts and authorized keys for the default scope and owner", async () => {
    seed();
    await mounted();

    expect(listKnownHosts).toHaveBeenCalledWith("global", "default");
    expect(listAuthorizedKeys).toHaveBeenCalledWith("global", "default");
    expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
    expect(screen.getByText("SHA256:pinnedpinned")).toBeInTheDocument();
    expect(screen.getByText("2026-11-01T10:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("deploy@ci")).toBeInTheDocument();
    expect(screen.getByText("no-pty, restrict")).toBeInTheDocument();
  });

  it("reloads both lists with a new scope and owner on Load", async () => {
    seed();
    await mounted();

    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "tenant" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "acme" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    await waitFor(() => expect(listKnownHosts).toHaveBeenLastCalledWith("tenant", "acme"));
    expect(listAuthorizedKeys).toHaveBeenLastCalledWith("tenant", "acme");
  });

  it("pins a known host and reloads", async () => {
    seed();
    addKnownHost.mockResolvedValue(undefined);
    await mounted();

    await fireEvent.input(screen.getByLabelText("Host"), { target: { value: "new.example.com" } });
    await fireEvent.input(screen.getByLabelText("Host fingerprint"), { target: { value: "SHA256:newnew" } });
    await fireEvent.input(screen.getByLabelText("Host algorithm"), { target: { value: "ecdsa-sha2-nistp256" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add pin" }));

    await waitFor(() =>
      expect(addKnownHost).toHaveBeenCalledWith({
        scope: "global",
        owner: "default",
        host: "new.example.com",
        fingerprint: "SHA256:newnew",
        algorithm: "ecdsa-sha2-nistp256",
      }),
    );
    await waitFor(() => expect(listKnownHosts).toHaveBeenCalledTimes(2));
  });

  it("removes a known host only after the confirm", async () => {
    seed();
    removeKnownHost.mockResolvedValue(undefined);
    await mounted();

    await fireEvent.click(screen.getByRole("button", { name: "Remove git.example.com" }));
    expect(await screen.findByText("Remove the pin for git.example.com?")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Confirm remove", hidden: true }));

    await waitFor(() => expect(removeKnownHost).toHaveBeenCalledWith("git.example.com", "global", "default"));
  });

  it("cancelling the remove confirm calls nothing", async () => {
    seed();
    await mounted();

    await fireEvent.click(screen.getByRole("button", { name: "Remove git.example.com" }));
    await screen.findByText("Remove the pin for git.example.com?");
    await fireEvent.click(screen.getByRole("button", { name: "Cancel", hidden: true }));

    await waitFor(() => expect(screen.queryByText("Remove the pin for git.example.com?")).not.toBeInTheDocument());
    expect(removeKnownHost).not.toHaveBeenCalled();
  });

  it("verifies a known host and shows the match", async () => {
    seed();
    verifyKnownHost.mockResolvedValue(undefined);
    await mounted();

    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered fingerprint"), { target: { value: "SHA256:pinnedpinned" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));

    await waitFor(() =>
      expect(verifyKnownHost).toHaveBeenCalledWith("git.example.com", {
        scope: "global",
        owner: "default",
        fingerprint: "SHA256:pinnedpinned",
      }),
    );
    expect(await screen.findByText("Fingerprint matches the pin for git.example.com.")).toBeInTheDocument();
  });

  it("shows a mismatch alert on a 409, not a toast", async () => {
    seed();
    verifyKnownHost.mockRejectedValue(
      Object.assign(new Error("pinned SHA256:pinnedpinned, offered SHA256:other"), { status: 409 }),
    );
    await mounted();

    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered fingerprint"), { target: { value: "SHA256:other" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));

    expect(await screen.findByText("Fingerprint mismatch")).toBeInTheDocument();
    expect(screen.getByText("pinned SHA256:pinnedpinned, offered SHA256:other")).toBeInTheDocument();
    expect(toasts).toEqual([]);
  });

  it("adds an authorized key with options split from a comma list", async () => {
    seed();
    addAuthorizedKey.mockResolvedValue(undefined);
    await mounted();

    await fireEvent.input(screen.getByLabelText("Key name"), { target: { value: "ops" } });
    await fireEvent.input(screen.getByLabelText("Authorized key line"), { target: { value: "ssh-ed25519 AAAAops ops@host" } });
    await fireEvent.input(screen.getByLabelText("Options"), { target: { value: "no-pty, restrict" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add key" }));

    await waitFor(() =>
      expect(addAuthorizedKey).toHaveBeenCalledWith({
        scope: "global",
        owner: "default",
        name: "ops",
        line: "ssh-ed25519 AAAAops ops@host",
        options: ["no-pty", "restrict"],
      }),
    );
    await waitFor(() => expect(listAuthorizedKeys).toHaveBeenCalledTimes(2));
  });

  it("omits options when the comma list is empty", async () => {
    seed();
    addAuthorizedKey.mockResolvedValue(undefined);
    await mounted();

    await fireEvent.input(screen.getByLabelText("Key name"), { target: { value: "ops" } });
    await fireEvent.input(screen.getByLabelText("Authorized key line"), { target: { value: "ssh-ed25519 AAAAops" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add key" }));

    await waitFor(() =>
      expect(addAuthorizedKey).toHaveBeenCalledWith({
        scope: "global",
        owner: "default",
        name: "ops",
        line: "ssh-ed25519 AAAAops",
      }),
    );
  });

  it("removes an authorized key after the confirm", async () => {
    seed();
    removeAuthorizedKey.mockResolvedValue(undefined);
    await mounted();

    await fireEvent.click(screen.getByRole("button", { name: "Remove deploy" }));
    expect(await screen.findByText("Remove the authorized key deploy?")).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Confirm remove", hidden: true }));

    await waitFor(() => expect(removeAuthorizedKey).toHaveBeenCalledWith("global", "default", "deploy"));
  });

  it("verifies an authorized key and names the matched entry", async () => {
    seed();
    verifyAuthorizedKey.mockResolvedValue(entry);
    await mounted();

    await fireEvent.input(screen.getByLabelText("Key fingerprint"), { target: { value: "SHA256:deploykey" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify key" }));

    await waitFor(() =>
      expect(verifyAuthorizedKey).toHaveBeenCalledWith({
        scope: "global",
        owner: "default",
        fingerprint: "SHA256:deploykey",
      }),
    );
    expect(await screen.findByText("Fingerprint matches deploy.")).toBeInTheDocument();
  });

  it("shows an error alert when the known-host list fails", async () => {
    listKnownHosts.mockRejectedValue(new Error("ssh store unavailable"));
    listAuthorizedKeys.mockResolvedValue({ items: [] });

    render(SshTrustView);

    expect(await screen.findByText("ssh store unavailable")).toBeInTheDocument();
  });

  it("keeps the row and toasts when removing an authorized key fails", async () => {
    seed();
    removeAuthorizedKey.mockRejectedValue(new Error("forbidden"));
    await mounted();

    await fireEvent.click(screen.getByRole("button", { name: "Remove deploy" }));
    await screen.findByText("Remove the authorized key deploy?");
    await fireEvent.click(screen.getByRole("button", { name: "Confirm remove", hidden: true }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "forbidden" }));
    expect(screen.getByText("deploy")).toBeInTheDocument();
  });
});
