import { writable, derived } from 'svelte/store';

export interface KeyEntry {
  id: string;
  alias: string;
  algorithm: string;
  backend: string;
  keyType: string;
  created: string;
  lastUsed: string | null;
  attestationStatus: string;
}

export interface KeysState {
  keys: KeyEntry[];
  loading: boolean;
  searchQuery: string;
  filterBackend: string | null;
  filterType: string | null;
}

const initialState: KeysState = {
  keys: [],
  loading: false,
  searchQuery: '',
  filterBackend: null,
  filterType: null,
};

export const keysState = writable<KeysState>(initialState);

export const keyList = derived(keysState, ($s) => {
  let result = $s.keys;

  if ($s.searchQuery) {
    const query = $s.searchQuery.toLowerCase();
    result = result.filter(
      (k) =>
        k.alias.toLowerCase().includes(query) ||
        k.algorithm.toLowerCase().includes(query) ||
        k.backend.toLowerCase().includes(query)
    );
  }

  if ($s.filterBackend) {
    result = result.filter((k) => k.backend === $s.filterBackend);
  }

  if ($s.filterType) {
    result = result.filter((k) => k.keyType === $s.filterType);
  }

  return result;
});

export const keyCount = derived(keysState, ($s) => $s.keys.length);

export const keyCounts = derived(keysState, ($s) => {
  const counts: Record<string, number> = {};
  for (const key of $s.keys) {
    const backend = key.backend;
    counts[backend] = (counts[backend] || 0) + 1;
  }
  return counts;
});

export const keyTypeCounts = derived(keysState, ($s) => {
  const counts: Record<string, number> = {};
  for (const key of $s.keys) {
    const kt = key.keyType;
    counts[kt] = (counts[kt] || 0) + 1;
  }
  return counts;
});

export function setKeys(keys: KeyEntry[]): void {
  keysState.update((s) => ({ ...s, keys }));
}

export function setKeysLoading(loading: boolean): void {
  keysState.update((s) => ({ ...s, loading }));
}

export function setSearchQuery(query: string): void {
  keysState.update((s) => ({ ...s, searchQuery: query }));
}

export function setFilterBackend(backend: string | null): void {
  keysState.update((s) => ({ ...s, filterBackend: backend }));
}

export function setFilterType(keyType: string | null): void {
  keysState.update((s) => ({ ...s, filterType: keyType }));
}

export function addKey(key: KeyEntry): void {
  keysState.update((s) => ({ ...s, keys: [...s.keys, key] }));
}

export function removeKey(id: string): void {
  keysState.update((s) => ({
    ...s,
    keys: s.keys.filter((k) => k.id !== id),
  }));
}
