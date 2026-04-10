import { writable, derived } from 'svelte/store';
import type { OIDCProviderEntry, OIDCTokenInfo, OIDCRefreshStatus } from '$lib/api/backend';

export interface OIDCState {
  providers: OIDCProviderEntry[];
  tokens: Record<string, OIDCTokenInfo>;
  refreshStatus: Record<string, OIDCRefreshStatus>;
  loading: boolean;
  searchQuery: string;
}

const initialState: OIDCState = {
  providers: [],
  tokens: {},
  refreshStatus: {},
  loading: false,
  searchQuery: '',
};

export const oidcState = writable<OIDCState>(initialState);

export const oidcProviders = derived(oidcState, ($s) => {
  if (!$s.searchQuery) return $s.providers;
  const query = $s.searchQuery.toLowerCase();
  return $s.providers.filter(
    (p) =>
      p.name.toLowerCase().includes(query) ||
      p.issuer.toLowerCase().includes(query) ||
      p.type.toLowerCase().includes(query)
  );
});

export const oidcProviderCount = derived(oidcState, ($s) => $s.providers.length);

export function setOIDCLoading(loading: boolean): void {
  oidcState.update((s) => ({ ...s, loading }));
}

export function setOIDCSearch(query: string): void {
  oidcState.update((s) => ({ ...s, searchQuery: query }));
}

export function setProviders(providers: OIDCProviderEntry[]): void {
  oidcState.update((s) => ({ ...s, providers }));
}

export function addProvider(provider: OIDCProviderEntry): void {
  oidcState.update((s) => ({ ...s, providers: [...s.providers, provider] }));
}

export function updateProvider(name: string, provider: OIDCProviderEntry): void {
  oidcState.update((s) => ({
    ...s,
    providers: s.providers.map((p) => (p.name === name ? provider : p)),
  }));
}

export function removeProvider(name: string): void {
  oidcState.update((s) => ({
    ...s,
    providers: s.providers.filter((p) => p.name !== name),
    tokens: (() => { const t = { ...s.tokens }; delete t[name]; return t; })(),
    refreshStatus: (() => { const r = { ...s.refreshStatus }; delete r[name]; return r; })(),
  }));
}

export function setToken(name: string, token: OIDCTokenInfo): void {
  oidcState.update((s) => ({
    ...s,
    tokens: { ...s.tokens, [name]: token },
  }));
}

export function removeToken(name: string): void {
  oidcState.update((s) => {
    const tokens = { ...s.tokens };
    delete tokens[name];
    return { ...s, tokens };
  });
}

export function setAllTokens(tokens: OIDCTokenInfo[]): void {
  oidcState.update((s) => {
    const tokenMap: Record<string, OIDCTokenInfo> = {};
    for (const t of tokens) {
      tokenMap[t.provider] = t;
    }
    return { ...s, tokens: tokenMap };
  });
}

export function setRefreshStatus(name: string, status: OIDCRefreshStatus): void {
  oidcState.update((s) => ({
    ...s,
    refreshStatus: { ...s.refreshStatus, [name]: status },
  }));
}

export function setAllRefreshStatus(statuses: OIDCRefreshStatus[]): void {
  oidcState.update((s) => {
    const statusMap: Record<string, OIDCRefreshStatus> = {};
    for (const rs of statuses) {
      statusMap[rs.provider] = rs;
    }
    return { ...s, refreshStatus: statusMap };
  });
}

let pollInterval: ReturnType<typeof setInterval> | null = null;

export function startStatusPolling(pollFn: () => void): void {
  if (pollInterval !== null) return;
  pollFn();
  pollInterval = setInterval(pollFn, 10000);
}

export function stopStatusPolling(): void {
  if (pollInterval !== null) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
}
