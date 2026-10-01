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
import type {
  OIDCAccessToken,
  OIDCCredential,
  OIDCCredentialCreateRequest,
  OIDCCredentialListResponse,
  OIDCCredentialRef,
  OIDCCredentialTokens,
  WaitForDeviceLoginOptions,
} from "@go-xkms/sdk";

const list = vi.fn<() => Promise<OIDCCredentialListResponse>>();
const create = vi.fn<(req: OIDCCredentialCreateRequest) => Promise<OIDCCredential>>();
const del = vi.fn<(ref: OIDCCredentialRef) => Promise<void>>();
const importTokens = vi.fn<(ref: OIDCCredentialRef, tokens: OIDCCredentialTokens) => Promise<OIDCCredential>>();
const refresh = vi.fn<(ref: OIDCCredentialRef) => Promise<OIDCCredential>>();
const getAccessToken = vi.fn<(ref: OIDCCredentialRef) => Promise<OIDCAccessToken>>();
const startDeviceLogin = vi.fn<(ref: OIDCCredentialRef) => Promise<OIDCCredential>>();
const waitForDeviceLogin =
  vi.fn<(c: OIDCCredential, opts?: WaitForDeviceLoginOptions) => Promise<OIDCCredential>>();

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    oidcCredentials: {
      list,
      create,
      delete: del,
      importTokens,
      refresh,
      getAccessToken,
      startDeviceLogin,
      waitForDeviceLogin,
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

import OidcCredentialsView from "../src/views/OidcCredentialsView.svelte";

function credential(over: Partial<OIDCCredential> = {}): OIDCCredential {
  return {
    scope: "tenant",
    name: "codex",
    config: { template: "openai" },
    status: "active",
    refreshable: true,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...over,
  };
}

const deviceLogin = {
  user_code: "WXYZ-1234",
  verification_uri: "https://auth.openai.com/codex/device",
  interval_seconds: 5,
  expires_at: "2099-01-01T00:00:00Z",
};

const writeText = vi.fn<(text: string) => Promise<void>>();

beforeEach(() => {
  vi.clearAllMocks();
  toasts.length = 0;
  writeText.mockResolvedValue(undefined);
  Object.assign(navigator, { clipboard: { writeText } });
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function openCreate(): Promise<void> {
  render(OidcCredentialsView);
  await screen.findByText("No shared credentials.");
  await fireEvent.click(screen.getByRole("button", { name: "+ Create" }));
}

describe("OidcCredentialsView", () => {
  it("lists shared and personal credentials apart, flagging the ones that need a login", async () => {
    list.mockResolvedValue({
      credentials: [
        credential(),
        credential({
          name: "entra",
          config: { template: "microsoft" },
          status: "relogin_required",
          status_reason: "refresh token revoked",
        }),
        credential({ scope: "user", owner: "alice", name: "claude", config: { template: "anthropic" }, status: "expired", refreshable: false }),
      ],
    });

    render(OidcCredentialsView);

    const sharedTable = (await screen.findByText("Shared with the tenant")).closest("table")!;
    const personalTable = screen.getByText("Personal (only you)").closest("table")!;
    expect(sharedTable).toHaveTextContent("codex");
    expect(sharedTable).toHaveTextContent("entra");
    expect(sharedTable).not.toHaveTextContent("claude");
    expect(personalTable).toHaveTextContent("claude");

    expect(screen.getByText("active")).toHaveClass("badge-success");
    expect(screen.getByText("re-login required")).toHaveClass("badge-error");
    expect(screen.getByText("refresh token revoked")).toHaveClass("text-error");
    expect(screen.getByText("expired")).toHaveClass("badge-error");

    // Only an active credential offers its token; only a refreshable one a
    // refresh; an import-only provider no device login.
    expect(screen.getByRole("button", { name: "Copy access token of codex" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy access token of entra" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Refresh claude" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Device login for claude" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Device login for entra" })).toBeInTheDocument();
    // No token is fetched just to render the list.
    expect(getAccessToken).not.toHaveBeenCalled();
  });

  it("shows both empty states with no credentials", async () => {
    list.mockResolvedValue({ credentials: [] });
    render(OidcCredentialsView);
    expect(await screen.findByText("No shared credentials.")).toBeInTheDocument();
    expect(screen.getByText("No personal credentials.")).toBeInTheDocument();
  });

  it("surfaces a load error instead of a blank page", async () => {
    list.mockRejectedValue(new Error("barrier sealed"));
    render(OidcCredentialsView);
    expect(await screen.findByText("barrier sealed")).toBeInTheDocument();
  });

  it("creates an openai credential and walks its device login to active", async () => {
    list.mockResolvedValue({ credentials: [] });
    const pending = credential({ status: "pending" });
    create.mockResolvedValue(pending);
    startDeviceLogin.mockResolvedValue({ ...pending, device_login: deviceLogin });
    let approve!: (c: OIDCCredential) => void;
    waitForDeviceLogin.mockReturnValue(new Promise((resolve) => (approve = resolve)));

    await openCreate();
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "codex" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toEqual({ scope: "tenant", name: "codex", config: { template: "openai" } });
    await waitFor(() => expect(startDeviceLogin).toHaveBeenCalledWith({ scope: "tenant", name: "codex" }));

    expect(await screen.findByText("WXYZ-1234")).toBeInTheDocument();
    const link = screen.getByRole("link", { name: deviceLogin.verification_uri, hidden: true });
    expect(link).toHaveAttribute("href", deviceLogin.verification_uri);
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(waitForDeviceLogin.mock.calls[0]![0].device_login).toEqual(deviceLogin);

    await fireEvent.click(screen.getByRole("button", { name: "Copy code", hidden: true }));
    expect(writeText).toHaveBeenCalledWith("WXYZ-1234");

    approve(credential());
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: '"codex" is logged in.' }));
    await waitFor(() => expect(screen.queryByText("WXYZ-1234")).not.toBeInTheDocument());
    expect(list).toHaveBeenCalledTimes(3);
  });

  it("reports a device login that settles without approval, and stops polling when closed", async () => {
    list.mockResolvedValue({ credentials: [credential({ status: "relogin_required" })] });
    startDeviceLogin.mockResolvedValue(credential({ status: "pending", device_login: deviceLogin }));
    waitForDeviceLogin.mockResolvedValue(credential({ status: "expired", status_reason: "device code expired" }));

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Device login for codex" }));

    expect(await screen.findByText("The login ended expired: device code expired.")).toBeInTheDocument();
    const signal = waitForDeviceLogin.mock.calls[0]![1]!.signal!;
    expect(signal.aborted).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Close", hidden: true }));
    expect(signal.aborted).toBe(true);
  });

  it("toasts a device login that cannot start", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    startDeviceLogin.mockRejectedValue(new Error("provider has no device endpoint"));

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Device login for codex" }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "provider has no device endpoint" }));
    expect(waitForDeviceLogin).not.toHaveBeenCalled();
  });

  it("creates a personal anthropic credential from an imported token", async () => {
    list.mockResolvedValue({ credentials: [] });
    create.mockResolvedValue(credential({ scope: "user", name: "claude" }));

    await openCreate();
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "claude" } });
    await fireEvent.change(screen.getByRole("combobox", { name: "Visibility", hidden: true }), { target: { value: "user" } });
    await fireEvent.change(screen.getByRole("combobox", { name: "Provider", hidden: true }), { target: { value: "anthropic" } });

    // Import is the only method: no method tabs, the token field is shown.
    expect(screen.queryByRole("tab", { hidden: true })).not.toBeInTheDocument();
    const createBtn = screen.getByRole("button", { name: "Create", hidden: true });
    expect(createBtn).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Token"), { target: { value: "sk-ant-oat01-x" } });
    await fireEvent.click(createBtn);

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0]).toEqual({
      scope: "user",
      name: "claude",
      config: { template: "anthropic" },
      tokens: { access_token: "sk-ant-oat01-x" },
    });
    expect(startDeviceLogin).not.toHaveBeenCalled();
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: 'OIDC credential "claude" created.' }));
  });

  it("requires an issuer and client ID for okta and sends them with the scopes", async () => {
    list.mockResolvedValue({ credentials: [] });
    create.mockResolvedValue(credential({ status: "pending", config: { template: "okta" } }));
    startDeviceLogin.mockResolvedValue(credential({ status: "pending", device_login: deviceLogin }));
    waitForDeviceLogin.mockReturnValue(new Promise(() => {}));

    await openCreate();
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "okta" } });
    await fireEvent.change(screen.getByRole("combobox", { name: "Provider", hidden: true }), { target: { value: "okta" } });
    const createBtn = screen.getByRole("button", { name: "Create", hidden: true });
    expect(createBtn).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Issuer URL"), { target: { value: "https://acme.okta.com" } });
    expect(createBtn).toBeDisabled();
    await fireEvent.input(screen.getByLabelText("Client ID"), { target: { value: "0oa1" } });
    await fireEvent.input(screen.getByLabelText("Scopes"), { target: { value: "openid offline_access" } });
    await fireEvent.click(createBtn);

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]![0].config).toEqual({
      template: "okta",
      issuer: "https://acme.okta.com",
      client_id: "0oa1",
      scopes: ["openid", "offline_access"],
    });
  });

  it("keeps the create dialog open with the server's refusal", async () => {
    list.mockResolvedValue({ credentials: [] });
    create.mockRejectedValue(new Error("credential already exists"));

    await openCreate();
    await fireEvent.input(screen.getByPlaceholderText("Name"), { target: { value: "codex" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create", hidden: true }));

    expect(await screen.findByText("credential already exists")).toBeInTheDocument();
    expect(startDeviceLogin).not.toHaveBeenCalled();
  });

  it("imports a pasted codex auth.json into a credential without logging it", async () => {
    const log = vi.spyOn(console, "log");
    const info = vi.spyOn(console, "info");
    const errorLog = vi.spyOn(console, "error");
    const personal = credential({ tenant_id: "t1", scope: "user", owner: "alice", name: "mine" });
    list.mockResolvedValue({ credentials: [personal] });
    importTokens.mockResolvedValue(personal);
    const authJson = JSON.stringify({ tokens: { access_token: "AT-secret", refresh_token: "RT-secret", id_token: "ID-secret" } });

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Import tokens into mine" }));
    const paste = screen.getByLabelText(/Paste a codex auth.json/);

    await fireEvent.input(paste, { target: { value: "{not json" } });
    await fireEvent.click(screen.getByRole("button", { name: "Fill from auth.json", hidden: true }));
    expect(screen.getByRole("alert", { hidden: true })).toHaveTextContent("Not valid JSON");

    await fireEvent.input(paste, { target: { value: authJson } });
    await fireEvent.click(screen.getByRole("button", { name: "Fill from auth.json", hidden: true }));
    expect(paste).toHaveValue("");
    expect(screen.getByLabelText("Access token")).toHaveValue("AT-secret");
    await fireEvent.click(screen.getByRole("button", { name: "Import", hidden: true }));

    await waitFor(() => expect(importTokens).toHaveBeenCalledOnce());
    expect(importTokens.mock.calls[0]).toEqual([
      { tenant_id: "t1", scope: "user", owner: "alice", name: "mine" },
      { access_token: "AT-secret", refresh_token: "RT-secret", id_token: "ID-secret" },
    ]);
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: 'Tokens imported into "mine".' }));
    const logged = [...log.mock.calls, ...info.mock.calls, ...errorLog.mock.calls].flat().map(String).join(" ");
    expect(logged).not.toMatch(/AT-secret|RT-secret|ID-secret/);
  });

  it("keeps the import dialog open with the server's refusal", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    importTokens.mockRejectedValue(new Error("token is not a JWT"));

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Import tokens into codex" }));
    await fireEvent.input(screen.getByLabelText("Access token"), { target: { value: "x" } });
    await fireEvent.click(screen.getByRole("button", { name: "Import", hidden: true }));

    expect(await screen.findByText("token is not a JWT")).toBeInTheDocument();
  });

  it("fetches an access token only on copy and puts it on the clipboard", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    getAccessToken.mockResolvedValue({ access_token: "live-token", token_type: "Bearer" });

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Copy access token of codex" }));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith("live-token"));
    expect(getAccessToken).toHaveBeenCalledWith({ scope: "tenant", name: "codex" });
    expect(toasts).toContainEqual({ kind: "success", message: 'Access token of "codex" copied.' });
    expect(document.body).not.toHaveTextContent("live-token");
  });

  it("toasts a refused token fetch without touching the clipboard", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    getAccessToken.mockRejectedValue(new Error("relogin required"));

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Copy access token of codex" }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "relogin required" }));
    expect(writeText).not.toHaveBeenCalled();
  });

  it("refreshes a credential and reloads, toasting a failure", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    refresh.mockResolvedValueOnce(credential()).mockRejectedValueOnce(new Error("invalid_grant"));

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Refresh codex" }));
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: '"codex" refreshed.' }));
    expect(list).toHaveBeenCalledTimes(2);

    await fireEvent.click(await screen.findByRole("button", { name: "Refresh codex" }));
    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "invalid_grant" }));
  });

  it("deletes a credential only after confirmation", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    del.mockResolvedValue(undefined);

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Delete codex" }));
    expect(del).not.toHaveBeenCalled();
    expect(screen.getByText('Delete "codex"?')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole("button", { name: "Delete", hidden: true }));

    await waitFor(() => expect(del).toHaveBeenCalledWith({ scope: "tenant", name: "codex" }));
    await waitFor(() => expect(toasts).toContainEqual({ kind: "success", message: 'OIDC credential "codex" deleted.' }));
  });

  it("toasts a refused delete", async () => {
    list.mockResolvedValue({ credentials: [credential()] });
    del.mockRejectedValue(new Error("permission denied"));

    render(OidcCredentialsView);
    await fireEvent.click(await screen.findByRole("button", { name: "Delete codex" }));
    await fireEvent.click(screen.getByRole("button", { name: "Delete", hidden: true }));

    await waitFor(() => expect(toasts).toContainEqual({ kind: "error", message: "permission denied" }));
  });
});
