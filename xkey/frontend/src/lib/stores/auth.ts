import { writable, derived } from 'svelte/store';
import type { AuthMode } from '$lib/types/setup';

/** Enterprise policy loaded from SetupWizardService.GetPolicy(). */
export const enterprisePolicy = writable<Record<string, any> | null>(null);

export function setEnterprisePolicy(p: Record<string, any> | null): void {
  enterprisePolicy.set(p);
}

export interface AuthState {
  mode: AuthMode;
  policyVerified: boolean;
  tamperDetected: boolean;
  enterpriseMode: boolean;
}

const initialState: AuthState = {
  mode: 'locked',
  policyVerified: false,
  tamperDetected: false,
  enterpriseMode: false,
};

export const authState = writable<AuthState>(initialState);

export const authMode = derived(authState, ($s) => $s.mode);
export const isPolicyVerified = derived(authState, ($s) => $s.policyVerified);
export const isTamperDetected = derived(authState, ($s) => $s.tamperDetected);
export const isEnterpriseMode = derived(authState, ($s) => $s.enterpriseMode);
export const isAuthenticated = derived(authState, ($s) => $s.mode !== 'locked');
export const isSOAdmin = derived(authState, ($s) => $s.mode === 'so_admin');

export function setAuthMode(mode: AuthMode): void {
  authState.update((s) => ({ ...s, mode }));
}

export function setEnterpriseMode(enterprise: boolean): void {
  authState.update((s) => ({ ...s, enterpriseMode: enterprise }));
}

export function setPolicyVerified(verified: boolean): void {
  authState.update((s) => ({ ...s, policyVerified: verified }));
}

export function setTamperDetected(detected: boolean): void {
  authState.update((s) => ({ ...s, tamperDetected: detected }));
}

export function resetAuth(): void {
  authState.set(initialState);
}
