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

/**
 * LoginView wires @go-xkms/svelte-auth's LoginPanel with this app's SDK
 * client, auth context and router. LoginPanel's own ceremony logic (the
 * anti-enumeration message collapse, begin/assertion/finish sequencing) is
 * covered upstream in sdk/ts/svelte-auth/test/LoginPanel.test.ts — these
 * tests instead pin the VIEW's own responsibility: the real auth store gets
 * configured, a successful login refreshes the session and navigates to
 * /dashboard, and a rejected login does neither.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/svelte";
import type { CredentialProvider, AuthClientHost } from "@go-xkms/svelte-auth";
import { configureAuthStore, setAuthStatus } from "@go-xkms/svelte-auth";

const me = vi.fn();
const webAuthnBeginLogin = vi.fn();
const webAuthnFinishLogin = vi.fn();
const capabilitiesGet = vi.fn();

// The auth store is typed against the full AuthApi surface even though
// these tests only exercise the passkey-login slice of it.
const fakeClient: AuthClientHost = {
  auth: {
    refresh: vi.fn(),
    validate: vi.fn(),
    logout: vi.fn(),
    me,
    webAuthnBeginLogin,
    webAuthnFinishLogin,
    webAuthnRegisterBegin: vi.fn(),
    webAuthnRegisterFinish: vi.fn(),
    webAuthnRegistrationStatus: vi.fn(),
    loginCert: vi.fn(),
  },
  capabilities: { get: capabilitiesGet },
};

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => fakeClient,
  resetSDKClient: () => {},
}));

const methodsMock = vi.fn<() => Promise<Array<"passkey" | "certificate">>>();
const getAssertion = vi.fn();
const loginCertificate = vi.fn();

const fakeProvider: CredentialProvider = {
  methods: methodsMock,
  getAssertion,
  createCredential: vi.fn(),
  loginCertificate,
};

vi.mock("../src/lib/auth.ts", () => ({
  getAuthContext: () => ({ provider: fakeProvider }),
  setupAuth: () => ({ provider: fakeProvider }),
}));

const loadSession = vi.fn();
vi.mock("../src/stores/session.svelte.ts", () => ({
  loadSession: () => loadSession(),
}));

const navigateTo = vi.fn();
vi.mock("../src/stores/router.svelte.ts", () => ({
  navigateTo: (path: string) => navigateTo(path),
}));

import LoginView from "../src/views/LoginView.svelte";

beforeEach(() => {
  vi.clearAllMocks();
  window.localStorage.clear();
  methodsMock.mockResolvedValue(["passkey", "certificate"]);
  capabilitiesGet.mockResolvedValue({ webauthn_enabled: true, piv_login_enabled: true });
  // Configures the SAME auth-store singleton LoginPanel imports internally,
  // so setAuthenticated() does not throw AuthNotConfiguredError.
  configureAuthStore({ client: fakeClient, storagePrefix: "xkms-test", apiPrefixes: ["/api/"] });
  setAuthStatus("pending");
});

describe("LoginView", () => {
  it("renders the passkey chooser with the xKMS Console branding", async () => {
    render(LoginView);

    expect(await screen.findByText("xKMS Console")).toBeInTheDocument();
    expect(
      await screen.findByRole("button", { name: "Sign in with passkey" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Sign in with certificate" }),
    ).toBeInTheDocument();
  });

  it("completes a passkey login, refreshes the session and navigates to /dashboard", async () => {
    webAuthnBeginLogin.mockResolvedValue({
      options: { publicKey: { challenge: "Y2hhbGxlbmdl" } },
      sessionId: "sess-1",
      userId: "user-1",
    });
    getAssertion.mockResolvedValue({
      id: "cred-1",
      rawId: "Y3JlZC0x",
      type: "public-key",
      response: { clientDataJSON: "Y2Q", authenticatorData: "YWQ", signature: "c2ln" },
      clientExtensionResults: {},
    });
    webAuthnFinishLogin.mockResolvedValue({
      token: "access-1",
      refresh_token: "refresh-1",
      user_id: "user-1",
    });
    me.mockResolvedValue({ subject: "user-1", permissions: {}, capabilities: {} });

    render(LoginView);

    const passkeyBtn = await screen.findByRole("button", { name: "Sign in with passkey" });
    await fireEvent.click(passkeyBtn);
    const identifierInput = await screen.findByLabelText("Email");
    await fireEvent.input(identifierInput, { target: { value: "alice@example.com" } });
    await fireEvent.click(screen.getByRole("button", { name: "Authenticate with passkey" }));

    await waitFor(() => expect(webAuthnFinishLogin).toHaveBeenCalledOnce());
    expect(webAuthnBeginLogin.mock.calls[0]![0]).toMatchObject({ email: "alice@example.com" });

    await waitFor(() => expect(loadSession).toHaveBeenCalledOnce());
    expect(navigateTo).toHaveBeenCalledWith("/dashboard");
    // The access token really was persisted before the view navigated away.
    expect(window.localStorage.getItem("xkms-test_token")).toBe("access-1");
  });

  it("shows the single anti-enumeration failure message and never navigates on a rejected login", async () => {
    webAuthnBeginLogin.mockRejectedValue(new Error("no such account"));

    render(LoginView);

    const passkeyBtn = await screen.findByRole("button", { name: "Sign in with passkey" });
    await fireEvent.click(passkeyBtn);
    const identifierInput = await screen.findByLabelText("Email");
    await fireEvent.input(identifierInput, { target: { value: "nobody@example.com" } });
    await fireEvent.click(screen.getByRole("button", { name: "Authenticate with passkey" }));

    expect(
      await screen.findByText("Sign-in failed. Check your details and try again."),
    ).toBeInTheDocument();
    // The real backend error detail must never reach the UI (anti-enumeration).
    expect(screen.queryByText("no such account")).toBeNull();
    expect(loadSession).not.toHaveBeenCalled();
    expect(navigateTo).not.toHaveBeenCalled();
  });

  it("navigates to /register from the enrollment link", async () => {
    render(LoginView);
    await screen.findByText("xKMS Console");

    await fireEvent.click(screen.getByRole("button", { name: "No passkey yet? Enroll one" }));

    expect(navigateTo).toHaveBeenCalledWith("/register");
  });
});
