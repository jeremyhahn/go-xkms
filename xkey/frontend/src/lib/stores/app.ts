import { writable, derived } from 'svelte/store';

export interface AppState {
  currentView: string;
  sidebarCollapsed: boolean;
  isAdmin: boolean;
  version: string;
  modalOpen: boolean;
  modalComponent: string | null;
  modalProps: Record<string, unknown>;
  setupComplete: boolean;
  devToolsEnabled: boolean;
  tpmAvailable: boolean;
  /** Stateful PIV backend selection — persists across view navigation. */
  pivBackend: string;
}

const initialState: AppState = {
  currentView: 'dashboard',
  sidebarCollapsed: false,
  isAdmin: false,
  version: '0.1.0',
  modalOpen: false,
  modalComponent: null,
  modalProps: {},
  setupComplete: true,
  devToolsEnabled: true,
  tpmAvailable: false,
  pivBackend: '',
};

export const appState = writable<AppState>(initialState);

export const currentView = derived(appState, ($s) => $s.currentView);
export const sidebarCollapsed = derived(appState, ($s) => $s.sidebarCollapsed);
export const isAdmin = derived(appState, ($s) => $s.isAdmin);
export const isModalOpen = derived(appState, ($s) => $s.modalOpen);
export const setupComplete = derived(appState, ($s) => $s.setupComplete);
export const devToolsEnabled = derived(appState, ($s) => $s.devToolsEnabled);
export const tpmAvailable = derived(appState, ($s) => $s.tpmAvailable);
export const pivBackend = derived(appState, ($s) => $s.pivBackend);

export function navigateTo(view: string): void {
  appState.update((s) => ({ ...s, currentView: view }));
}

export function toggleSidebar(): void {
  appState.update((s) => ({ ...s, sidebarCollapsed: !s.sidebarCollapsed }));
}

export function collapseSidebar(): void {
  appState.update((s) => ({ ...s, sidebarCollapsed: true }));
}

export function expandSidebar(): void {
  appState.update((s) => ({ ...s, sidebarCollapsed: false }));
}

export function openModal(component: string, props: Record<string, unknown> = {}): void {
  appState.update((s) => ({
    ...s,
    modalOpen: true,
    modalComponent: component,
    modalProps: props,
  }));
}

export function closeModal(): void {
  appState.update((s) => ({
    ...s,
    modalOpen: false,
    modalComponent: null,
    modalProps: {},
  }));
}

export function setAdmin(value: boolean): void {
  appState.update((s) => ({ ...s, isAdmin: value }));
}

export function setSetupComplete(value: boolean): void {
  appState.update((s) => ({ ...s, setupComplete: value }));
}

export function setDevToolsEnabled(value: boolean): void {
  appState.update((s) => ({ ...s, devToolsEnabled: value }));
}

export function setTPMAvailable(value: boolean): void {
  appState.update((s) => ({ ...s, tpmAvailable: value }));
}

export function setPIVBackend(backend: string): void {
  appState.update((s) => ({ ...s, pivBackend: backend }));
}
