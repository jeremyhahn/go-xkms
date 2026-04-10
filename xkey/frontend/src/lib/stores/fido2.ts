import { writable, derived } from 'svelte/store';

export interface FIDO2Credential {
  id: string;
  relyingPartyId: string;
  relyingPartyName: string;
  userName: string;
  userDisplayName: string;
  algorithm: string;
  keyType: string;
  credProtect: number;
  backendType: string;
  useCount: number;
  discoverable: boolean;
  created: string;
  lastUsed: string | null;
}

export interface RelyingParty {
  id: string;
  name: string;
  credentialCount: number;
}

export interface BridgeStatus {
  running: boolean;
  deviceName: string | null;
  connectionType: string | null;
  uptime: number;
  recentAuthentications: BridgeAuthentication[];
}

export interface BridgeAuthentication {
  relyingParty: string;
  timestamp: string;
  success: boolean;
}

export interface FIDO2State {
  credentials: FIDO2Credential[];
  relyingParties: RelyingParty[];
  bridgeStatus: BridgeStatus;
  loading: boolean;
  searchQuery: string;
}

const initialBridgeStatus: BridgeStatus = {
  running: false,
  deviceName: null,
  connectionType: null,
  uptime: 0,
  recentAuthentications: [],
};

const initialState: FIDO2State = {
  credentials: [],
  relyingParties: [],
  bridgeStatus: initialBridgeStatus,
  loading: false,
  searchQuery: '',
};

export const fido2State = writable<FIDO2State>(initialState);

export const fido2Credentials = derived(fido2State, ($s) => {
  if (!$s.searchQuery) return $s.credentials;
  const query = $s.searchQuery.toLowerCase();
  return $s.credentials.filter(
    (c) =>
      c.relyingPartyName.toLowerCase().includes(query) ||
      c.userName.toLowerCase().includes(query) ||
      c.relyingPartyId.toLowerCase().includes(query)
  );
});

export const fido2CredentialCount = derived(fido2State, ($s) => $s.credentials.length);
export const bridgeStatus = derived(fido2State, ($s) => $s.bridgeStatus);
export const isBridgeRunning = derived(fido2State, ($s) => $s.bridgeStatus.running);

export function setCredentials(credentials: FIDO2Credential[]): void {
  fido2State.update((s) => ({ ...s, credentials }));
}

export function setRelyingParties(rps: RelyingParty[]): void {
  fido2State.update((s) => ({ ...s, relyingParties: rps }));
}

export function setBridgeStatus(status: BridgeStatus): void {
  fido2State.update((s) => ({ ...s, bridgeStatus: status }));
}

export function setFIDO2Loading(loading: boolean): void {
  fido2State.update((s) => ({ ...s, loading }));
}

export function setFIDO2Search(query: string): void {
  fido2State.update((s) => ({ ...s, searchQuery: query }));
}

export function addCredential(credential: FIDO2Credential): void {
  fido2State.update((s) => ({
    ...s,
    credentials: [...s.credentials, credential],
  }));
}

export function removeCredential(id: string): void {
  fido2State.update((s) => ({
    ...s,
    credentials: s.credentials.filter((c) => c.id !== id),
  }));
}

export function addBridgeAuthentication(auth: BridgeAuthentication): void {
  fido2State.update((s) => ({
    ...s,
    bridgeStatus: {
      ...s.bridgeStatus,
      recentAuthentications: [auth, ...s.bridgeStatus.recentAuthentications].slice(0, 20),
    },
  }));
}
