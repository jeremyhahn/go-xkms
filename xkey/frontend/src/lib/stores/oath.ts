import { writable, derived } from 'svelte/store';

export interface OATHAccount {
  id: string;
  issuer: string;
  accountName: string;
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  digits: 6 | 8;
  period: number;
  type: 'TOTP' | 'HOTP';
  currentCode: string | null;
  nextRotation: number;
  created: string;
  lastUsed: string | null;
}

export interface OATHState {
  accounts: OATHAccount[];
  loading: boolean;
  searchQuery: string;
  timerSeconds: number;
}

const initialState: OATHState = {
  accounts: [],
  loading: false,
  searchQuery: '',
  timerSeconds: 30,
};

export const oathState = writable<OATHState>(initialState);

export const oathAccounts = derived(oathState, ($s) => {
  if (!$s.searchQuery) return $s.accounts;
  const query = $s.searchQuery.toLowerCase();
  return $s.accounts.filter(
    (a) =>
      a.issuer.toLowerCase().includes(query) ||
      a.accountName.toLowerCase().includes(query)
  );
});

export const oathCount = derived(oathState, ($s) => $s.accounts.length);

export const currentTimerSeconds = derived(oathState, ($s) => $s.timerSeconds);

let timerInterval: ReturnType<typeof setInterval> | null = null;

export function startOATHTimer(): void {
  if (timerInterval !== null) return;

  function updateTimer(): void {
    const now = Math.floor(Date.now() / 1000);
    const remaining = 30 - (now % 30);
    oathState.update((s) => ({ ...s, timerSeconds: remaining }));
  }

  updateTimer();
  timerInterval = setInterval(updateTimer, 1000);
}

export function stopOATHTimer(): void {
  if (timerInterval !== null) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
}

export function setAccounts(accounts: OATHAccount[]): void {
  oathState.update((s) => ({ ...s, accounts }));
}

export function setOATHLoading(loading: boolean): void {
  oathState.update((s) => ({ ...s, loading }));
}

export function setOATHSearch(query: string): void {
  oathState.update((s) => ({ ...s, searchQuery: query }));
}

export function updateAccountCode(id: string, code: string, nextRotation: number): void {
  oathState.update((s) => ({
    ...s,
    accounts: s.accounts.map((a) =>
      a.id === id ? { ...a, currentCode: code, nextRotation } : a
    ),
  }));
}

export function addAccount(account: OATHAccount): void {
  oathState.update((s) => ({ ...s, accounts: [...s.accounts, account] }));
}

export function removeAccount(id: string): void {
  oathState.update((s) => ({
    ...s,
    accounts: s.accounts.filter((a) => a.id !== id),
  }));
}
