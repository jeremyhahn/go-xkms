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
  scope: "tenant",
  owner: "acme",
  host: "git.example.com",
  fingerprint: "SHA256:pinnedpinned",
  algorithm: "ssh-ed25519",
  added_at: "2026-11-01T10:00:00Z",
};

// authorized_keys-format host keys, the shape the server parses with
// ssh.ParseAuthorizedKey on Add and Verify.
const hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl new.example.com";
const otherHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3W7ffHMb3S+Z2lW0Kp9xQZkGg8bTqzZcCQ1fPQwNzR other";

const entry: SSHAuthorizedEntry = {
  scope: "tenant",
  owner: "acme",
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

// mountedInScope types a server-valid scope (pkg/scope: tenant, user or
// service) and its owner into the inputs, as an operator does before adding.
async function mountedInScope(): Promise<void> {
  await mounted();
  await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "tenant" } });
  await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "acme" } });
}

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
});

describe("SshTrustView", () => {
  it("loads unfiltered on mount; pkg/scope rejects any scope but tenant, user or service", async () => {
    seed();
    await mounted();

    // An empty scope and owner list every pin the caller may read; the old
    // "global" default failed pkg/scope.Parse on every mount.
    expect(listKnownHosts).toHaveBeenCalledWith(undefined, undefined);
    expect(listAuthorizedKeys).toHaveBeenCalledWith(undefined, undefined);
    expect(screen.getByLabelText("Scope")).toHaveValue("");
    expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
    expect(screen.getByText("SHA256:pinnedpinned")).toBeInTheDocument();
    expect(screen.getByText("2026-11-01T10:00:00Z")).toBeInTheDocument();
    expect(screen.getByText("deploy@ci")).toBeInTheDocument();
    expect(screen.getByText("no-pty, restrict")).toBeInTheDocument();
  });

  it("reloads both lists with a new scope and owner on Load", async () => {
    seed();
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "tenant" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "acme" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));

    await waitFor(() => expect(listKnownHosts).toHaveBeenLastCalledWith("tenant", "acme"));
    expect(listAuthorizedKeys).toHaveBeenLastCalledWith("tenant", "acme");
  });

  it("pins a known host and reloads", async () => {
    seed();
    addKnownHost.mockResolvedValue(undefined);
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Host"), { target: { value: "new.example.com" } });
    await fireEvent.input(screen.getByLabelText("Host public key"), { target: { value: hostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Add pin" }));

    // The server derives fingerprint and algorithm from public_key and
    // refuses an Add without it (embeddedKnownHostsClient.Add).
    await waitFor(() =>
      expect(addKnownHost).toHaveBeenCalledWith({
        scope: "tenant",
        owner: "acme",
        host: "new.example.com",
        public_key: hostKey,
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

    await waitFor(() => expect(removeKnownHost).toHaveBeenCalledWith("git.example.com", "tenant", "acme"));
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
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: hostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));

    await waitFor(() =>
      expect(verifyKnownHost).toHaveBeenCalledWith("git.example.com", {
        scope: "tenant",
        owner: "acme",
        public_key: hostKey,
      }),
    );
    expect(await screen.findByText("Fingerprint matches the pin for git.example.com.")).toBeInTheDocument();
  });

  it("shows a mismatch alert on a 409, not a toast", async () => {
    seed();
    verifyKnownHost.mockRejectedValue(
      Object.assign(new Error("pinned SHA256:pinnedpinned, offered SHA256:other"), { status: 409 }),
    );
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: otherHostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));

    expect(await screen.findByText("Fingerprint mismatch")).toBeInTheDocument();
    expect(screen.getByText("pinned SHA256:pinnedpinned, offered SHA256:other")).toBeInTheDocument();
    expect(toasts).toEqual([]);
  });

  it("adds an authorized key with options split from a comma list", async () => {
    seed();
    addAuthorizedKey.mockResolvedValue(undefined);
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Key name"), { target: { value: "ops" } });
    await fireEvent.input(screen.getByLabelText("Authorized key line"), { target: { value: "ssh-ed25519 AAAAops ops@host" } });
    await fireEvent.input(screen.getByLabelText("Options"), { target: { value: "no-pty, restrict" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add key" }));

    await waitFor(() =>
      expect(addAuthorizedKey).toHaveBeenCalledWith({
        scope: "tenant",
        owner: "acme",
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
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Key name"), { target: { value: "ops" } });
    await fireEvent.input(screen.getByLabelText("Authorized key line"), { target: { value: "ssh-ed25519 AAAAops" } });
    await fireEvent.click(screen.getByRole("button", { name: "Add key" }));

    await waitFor(() =>
      expect(addAuthorizedKey).toHaveBeenCalledWith({
        scope: "tenant",
        owner: "acme",
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

    await waitFor(() => expect(removeAuthorizedKey).toHaveBeenCalledWith("tenant", "acme", "deploy"));
  });

  it("verifies an authorized key and names the matched entry", async () => {
    seed();
    verifyAuthorizedKey.mockResolvedValue(entry);
    await mountedInScope();

    await fireEvent.input(screen.getByLabelText("Key fingerprint"), { target: { value: "SHA256:deploykey" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify key" }));

    await waitFor(() =>
      expect(verifyAuthorizedKey).toHaveBeenCalledWith({
        scope: "tenant",
        owner: "acme",
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

  it("removes with the displayed row's scope and owner after the inputs are edited", async () => {
    const pinA = { ...pin, scope: "tenant", owner: "acme" };
    const entryA = { ...entry, scope: "tenant", owner: "acme" };
    listKnownHosts.mockResolvedValue({ items: [pinA] });
    listAuthorizedKeys.mockResolvedValue({ items: [entryA] });
    removeKnownHost.mockResolvedValue(undefined);
    removeAuthorizedKey.mockResolvedValue(undefined);
    await mounted();

    // Load scope A, then edit the inputs to scope B without loading it.
    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "tenant" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "acme" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(listKnownHosts).toHaveBeenLastCalledWith("tenant", "acme"));
    await screen.findByText("git.example.com");
    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "user" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "bob" } });

    await fireEvent.click(screen.getByRole("button", { name: "Remove git.example.com" }));
    await screen.findByText("Remove the pin for git.example.com?");
    await fireEvent.click(screen.getByRole("button", { name: "Confirm remove", hidden: true }));
    await waitFor(() => expect(removeKnownHost).toHaveBeenCalledWith("git.example.com", "tenant", "acme"));

    await screen.findByText("deploy");
    await fireEvent.click(screen.getByRole("button", { name: "Remove deploy" }));
    await screen.findByText("Remove the authorized key deploy?");
    await fireEvent.click(screen.getByRole("button", { name: "Confirm remove", hidden: true }));
    await waitFor(() => expect(removeAuthorizedKey).toHaveBeenCalledWith("tenant", "acme", "deploy"));
  });
});

describe("SshTrustView duplicate names across scopes", () => {
  it("renders a tenant and a user record with the same host or name", async () => {
    const userPin = { ...pin, scope: "user", owner: "alice", fingerprint: "SHA256:userpin" };
    const userEntry: SSHAuthorizedEntry = { ...entry, scope: "user", owner: "alice", comment: "alice@laptop" };
    listKnownHosts.mockResolvedValue({ items: [pin, userPin] });
    listAuthorizedKeys.mockResolvedValue({ items: [entry, userEntry] });

    render(SshTrustView);

    expect(await screen.findByText("SHA256:userpin")).toBeInTheDocument();
    expect(screen.getByText("SHA256:pinnedpinned")).toBeInTheDocument();
    expect(screen.getByText("alice@laptop")).toBeInTheDocument();
    expect(screen.getByText("deploy@ci")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Remove git.example.com" })).toHaveLength(2);
    expect(screen.getAllByRole("button", { name: "Remove deploy" })).toHaveLength(2);
  });
});

describe("SshTrustView stale replies", () => {
  beforeEach(() => {
    seed();
  });

  async function settle(): Promise<void> {
    await new Promise((r) => setTimeout(r, 0));
    await new Promise((r) => setTimeout(r, 0));
  }

  it("drops a list reply that lands after the scope or owner changed", async () => {
    await mounted();
    let resolveHosts: (v: SSHPinListResponse) => void = () => {};
    listKnownHosts.mockImplementationOnce(() => new Promise((r) => (resolveHosts = r)));
    listAuthorizedKeys.mockResolvedValueOnce({ items: [] });
    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "user" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "bob" } });
    await fireEvent.click(screen.getByRole("button", { name: "Load" }));
    await waitFor(() => expect(listKnownHosts).toHaveBeenLastCalledWith("user", "bob"));

    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "carol" } });
    resolveHosts({ items: [{ ...pin, scope: "user", owner: "bob", host: "bob.example.com" }] });
    await settle();

    expect(screen.queryByText("bob.example.com")).not.toBeInTheDocument();
  });

  it("drops a host verify reply that lands after the host changed", async () => {
    await mountedInScope();
    let resolveVerify: () => void = () => {};
    verifyKnownHost.mockImplementationOnce(() => new Promise<void>((r) => (resolveVerify = r)));
    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: hostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));
    await waitFor(() => expect(verifyKnownHost).toHaveBeenCalledOnce());

    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "other.example.com" } });
    resolveVerify();
    await settle();

    expect(screen.queryByText(/Fingerprint matches the pin/)).not.toBeInTheDocument();
  });

  it("drops a key verify reply that lands after the fingerprint changed", async () => {
    await mountedInScope();
    let resolveVerify: (e: SSHAuthorizedEntry) => void = () => {};
    verifyAuthorizedKey.mockImplementationOnce(() => new Promise<SSHAuthorizedEntry>((r) => (resolveVerify = r)));
    await fireEvent.input(screen.getByLabelText("Key fingerprint"), { target: { value: "SHA256:one" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify key" }));
    await waitFor(() => expect(verifyAuthorizedKey).toHaveBeenCalledOnce());

    await fireEvent.input(screen.getByLabelText("Key fingerprint"), { target: { value: "SHA256:two" } });
    resolveVerify(entry);
    await settle();

    expect(screen.queryByText(/Fingerprint matches deploy/)).not.toBeInTheDocument();
  });

  it("freezes scope and owner while an add is pending", async () => {
    await mountedInScope();
    let resolveAdd: () => void = () => {};
    addKnownHost.mockImplementationOnce(() => new Promise<void>((r) => (resolveAdd = r)));
    await fireEvent.input(screen.getByLabelText("Host"), { target: { value: "new.example.com" } });
    await fireEvent.input(screen.getByLabelText("Host public key"), { target: { value: hostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Add pin" }));
    await waitFor(() => expect(addKnownHost).toHaveBeenCalledOnce());

    expect(screen.getByLabelText("Scope")).toBeDisabled();
    expect(screen.getByLabelText("Owner")).toBeDisabled();
    resolveAdd();
    await waitFor(() => expect(screen.getByLabelText("Scope")).not.toBeDisabled());
  });
});

describe("SshTrustView verdicts after an edit", () => {
  beforeEach(() => {
    seed();
  });

  async function verifiedHost(): Promise<void> {
    await mountedInScope();
    verifyKnownHost.mockResolvedValue(undefined);
    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: hostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));
    expect(await screen.findByText("Fingerprint matches the pin for git.example.com.")).toBeInTheDocument();
  }

  it("hides a host match once the offered key is replaced, until it is verified again", async () => {
    await verifiedHost();
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: otherHostKey } });
    expect(screen.queryByText(/Fingerprint matches/)).not.toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: hostKey } });
    expect(screen.getByText("Fingerprint matches the pin for git.example.com.")).toBeInTheDocument();
  });

  it("hides a host match once the scope or owner changes", async () => {
    await verifiedHost();
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "other" } });
    expect(screen.queryByText(/Fingerprint matches/)).not.toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "acme" } });
    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "user" } });
    expect(screen.queryByText(/Fingerprint matches/)).not.toBeInTheDocument();
  });

  it("hides a host mismatch once the host changes", async () => {
    await mountedInScope();
    verifyKnownHost.mockRejectedValue(Object.assign(new Error("fingerprint differs"), { status: 409 }));
    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "git.example.com" } });
    await fireEvent.input(screen.getByLabelText("Offered public key"), { target: { value: hostKey } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify host" }));
    expect(await screen.findByText("fingerprint differs")).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Host to verify"), { target: { value: "other.example.com" } });
    expect(screen.queryByText("fingerprint differs")).not.toBeInTheDocument();
  });

  it("hides an authorized-key match once the fingerprint, scope or owner changes", async () => {
    await mountedInScope();
    verifyAuthorizedKey.mockResolvedValue(entry);
    const fp = screen.getByLabelText("Key fingerprint");
    await fireEvent.input(fp, { target: { value: "SHA256:deploy" } });
    await fireEvent.click(screen.getByRole("button", { name: "Verify key" }));
    expect(await screen.findByText("Fingerprint matches deploy.")).toBeInTheDocument();

    await fireEvent.input(fp, { target: { value: "SHA256:other" } });
    expect(screen.queryByText("Fingerprint matches deploy.")).not.toBeInTheDocument();
    await fireEvent.input(fp, { target: { value: "SHA256:deploy" } });
    expect(screen.getByText("Fingerprint matches deploy.")).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "service" } });
    expect(screen.queryByText("Fingerprint matches deploy.")).not.toBeInTheDocument();
    await fireEvent.input(screen.getByLabelText("Scope"), { target: { value: "tenant" } });
    await fireEvent.input(screen.getByLabelText("Owner"), { target: { value: "bob" } });
    expect(screen.queryByText("Fingerprint matches deploy.")).not.toBeInTheDocument();
  });
});
