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
  AttestationCredentialJSON,
  AuthMeResponse,
  WebAuthnAuthResponse,
  WebAuthnBeginRegistrationRequest,
  WebAuthnCeremonyStart,
} from "@go-xkms/sdk";
// The real (unmocked) svelte-auth token store — RegisterPanel calls
// setAuthenticated() on success, which throws AuthNotConfiguredError unless
// configureAuthStore() ran first. In the real app that happens inside
// $lib/auth.ts's setupAuth(), which this file mocks away below, so the test
// must configure the store itself.
import type { AuthClientHost } from "@go-xkms/svelte-auth";
import { configureAuthStore } from "@go-xkms/svelte-auth";

// RegisterView is a thin wiring shell around the real RegisterPanel (rendered
// unmocked below) — begin/finish/me go through the SDK client, the
// attestation ceremony goes through the CredentialProvider.
//
// vi.mock factories are hoisted above every other top-level statement in the
// file (all four calls move together, ahead of any local const), so the
// mocks they close over must themselves be created inside vi.hoisted —
// the only construct Vitest guarantees runs before the hoisted mock calls.
const {
  mockWebAuthnRegisterBegin,
  mockWebAuthnRegisterFinish,
  mockAuthMe,
  mockCreateCredential,
  mockLoadSession,
  mockNavigateTo,
} = vi.hoisted(() => ({
  mockWebAuthnRegisterBegin: vi.fn<(req: WebAuthnBeginRegistrationRequest) => Promise<WebAuthnCeremonyStart>>(),
  mockWebAuthnRegisterFinish: vi.fn<(sessionId: string, cred: AttestationCredentialJSON) => Promise<WebAuthnAuthResponse>>(),
  mockAuthMe: vi.fn<() => Promise<AuthMeResponse>>(),
  mockCreateCredential: vi.fn<(options: unknown) => Promise<AttestationCredentialJSON>>(),
  mockLoadSession: vi.fn<() => Promise<void>>(),
  mockNavigateTo: vi.fn<(path: string) => void>(),
}));

vi.mock("../src/stores/sdkClient.ts", () => ({
  getSDKClient: () => ({
    auth: {
      webAuthnRegisterBegin: mockWebAuthnRegisterBegin,
      webAuthnRegisterFinish: mockWebAuthnRegisterFinish,
      me: mockAuthMe,
    },
  }),
  resetSDKClient: () => {},
}));

vi.mock("../src/lib/auth.ts", () => ({
  getAuthContext: () => ({
    provider: {
      methods: vi.fn(),
      getAssertion: vi.fn(),
      createCredential: mockCreateCredential,
      loginCertificate: vi.fn(),
    },
  }),
  setupAuth: () => ({}),
}));

vi.mock("../src/stores/session.svelte.ts", () => ({
  loadSession: mockLoadSession,
}));

vi.mock("../src/stores/router.svelte.ts", () => ({
  navigateTo: mockNavigateTo,
}));

import RegisterView from "../src/views/RegisterView.svelte";

const fakeCredential = {
  id: "cred-1",
  rawId: "cred-1",
  type: "public-key",
  response: { clientDataJSON: "", attestationObject: "" },
} as unknown as AttestationCredentialJSON;

beforeEach(() => {
  vi.clearAllMocks();
  configureAuthStore({ client: {} as AuthClientHost, storagePrefix: "xkms-test" });
});

describe("RegisterView", () => {
  it("drives begin -> ceremony -> finish and hands the session off on success", async () => {
    mockWebAuthnRegisterBegin.mockResolvedValue({ options: { publicKey: {} }, sessionId: "sess-1" });
    mockCreateCredential.mockResolvedValue(fakeCredential);
    mockWebAuthnRegisterFinish.mockResolvedValue({ token: "at-1", refresh_token: "rt-1", user_id: "u1" });
    mockAuthMe.mockResolvedValue({
      subject: "u1",
      username: "alice",
      roles: [],
      permissions: {},
      capabilities: {},
    } as AuthMeResponse);

    render(RegisterView);

    await fireEvent.input(screen.getByLabelText("Email"), { target: { value: "alice@example.com" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create account with passkey" }));

    await waitFor(() => expect(mockWebAuthnRegisterFinish).toHaveBeenCalledOnce());
    // Only the identifier is sent when no display name was entered.
    expect(mockWebAuthnRegisterBegin.mock.calls[0]![0]).toEqual({ email: "alice@example.com" });
    expect(mockCreateCredential).toHaveBeenCalledWith({ publicKey: {} });
    expect(mockWebAuthnRegisterFinish.mock.calls[0]![0]).toBe("sess-1");
    expect(mockWebAuthnRegisterFinish.mock.calls[0]![1]).toBe(fakeCredential);

    await waitFor(() => expect(mockNavigateTo).toHaveBeenCalledWith("/dashboard"));
    expect(mockLoadSession).toHaveBeenCalledOnce();
  });

  it("includes a trimmed display name in the begin request when supplied", async () => {
    mockWebAuthnRegisterBegin.mockResolvedValue({ options: { publicKey: {} }, sessionId: "sess-2" });
    mockCreateCredential.mockResolvedValue(fakeCredential);
    mockWebAuthnRegisterFinish.mockResolvedValue({ token: "at-2", user_id: "u2" });
    mockAuthMe.mockResolvedValue({ subject: "u2", username: "bob", roles: [], permissions: {}, capabilities: {} } as AuthMeResponse);

    render(RegisterView);

    await fireEvent.input(screen.getByLabelText("Email"), { target: { value: "bob@example.com" } });
    await fireEvent.input(screen.getByLabelText("Display name"), { target: { value: "  Bob  " } });
    await fireEvent.click(screen.getByRole("button", { name: "Create account with passkey" }));

    await waitFor(() => expect(mockWebAuthnRegisterBegin).toHaveBeenCalledOnce());
    expect(mockWebAuthnRegisterBegin.mock.calls[0]![0]).toEqual({ email: "bob@example.com", display_name: "Bob" });
  });

  it("surfaces the registration-refused message on a 403 without running the ceremony", async () => {
    const forbidden = Object.assign(new Error("forbidden"), { status: 403 });
    mockWebAuthnRegisterBegin.mockRejectedValue(forbidden);

    render(RegisterView);

    await fireEvent.input(screen.getByLabelText("Email"), { target: { value: "alice@example.com" } });
    await fireEvent.click(screen.getByRole("button", { name: "Create account with passkey" }));

    expect(
      await screen.findByText(
        "Registration is not available for this address. If you already have a passkey, sign in and add another from your account; otherwise ask your admin.",
      ),
    ).toBeInTheDocument();
    expect(mockCreateCredential).not.toHaveBeenCalled();
    expect(mockNavigateTo).not.toHaveBeenCalled();
  });

  it("never begins the ceremony without an identifier", async () => {
    render(RegisterView);

    expect(screen.getByRole("button", { name: "Create account with passkey" })).toBeDisabled();
    expect(mockWebAuthnRegisterBegin).not.toHaveBeenCalled();
  });

  it("offers a path back to sign-in for an already-enrolled operator", async () => {
    render(RegisterView);

    await fireEvent.click(screen.getByRole("button", { name: "Already enrolled? Sign in" }));

    expect(mockNavigateTo).toHaveBeenCalledWith("/login");
  });
});
