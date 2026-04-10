import { writable, derived } from 'svelte/store';
import { backendMeta, type BackendMeta } from '$lib/utils/backends';

export interface BackendScopeState {
  /** null means "All Backends" (no filter) */
  activeBackend: string | null;
  /** List of available backend IDs, populated at runtime */
  availableBackends: string[];
}

const initialState: BackendScopeState = {
  activeBackend: null,
  availableBackends: [],
};

export const backendScope = writable<BackendScopeState>(initialState);

/** The currently active backend filter, or null for all */
export const activeBackend = derived(backendScope, ($s) => $s.activeBackend);

/** Available backends with their metadata */
export const availableBackendsMeta = derived(backendScope, ($s) => {
  return $s.availableBackends.map((id) => ({
    id,
    ...(backendMeta[id] ?? { label: id, icon: '', hardware: false }),
  }));
});

export function setActiveBackend(backend: string | null): void {
  backendScope.update((s) => ({ ...s, activeBackend: backend }));
}

export function setAvailableBackends(backends: string[]): void {
  backendScope.update((s) => ({ ...s, availableBackends: backends }));
}
