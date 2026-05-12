/**
 * Auth factor store — manages the user's registered auth factors in the
 * xkey desktop GUI. Mirrors the AuthFactor data model from §5e of the
 * bootstrap-auth-architecture spec.
 */

import { writable, derived } from 'svelte/store';
import { callBackend } from '$lib/api/backend';

export type AuthFactorType = 'mtls' | 'fido2' | 'piv';

export interface AuthFactor {
  id: string;
  user_id: string;
  type: AuthFactorType;
  label: string;
  metadata: Record<string, string>;
  registered_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_by: 'self' | 'admin' | 'ceremony';
}

export interface ListFactorsResponse {
  factors: AuthFactor[];
  total: number;
}

export interface AddFactorRequest {
  type: AuthFactorType;
  label: string;
  cert_pem?: string;
  webauthn_response?: string;
  piv_cert_pem?: string;
  piv_slot?: string;
}

export interface AddFactorResponse {
  factor: AuthFactor;
}

export interface RotateFactorRequest {
  factor_id: string;
  cert_pem?: string;
  webauthn_response?: string;
  piv_cert_pem?: string;
  piv_slot?: string;
}

export interface PIVCardInfo {
  reader_name: string;
  card_vendor: string;
  serial_number?: string;
  has_piv_applet: boolean;
}

export interface MFAPolicyRequest {
  tenant_id: string;
  require_factor_count: number;
}

export interface FactorState {
  factors: AuthFactor[];
  loading: boolean;
  error: string | null;
}

const initialState: FactorState = {
  factors: [],
  loading: false,
  error: null,
};

export const factorState = writable<FactorState>(initialState);

export const activeFactors = derived(factorState, ($s) =>
  $s.factors.filter((f) => !f.revoked_at)
);

export const factorsByType = derived(activeFactors, ($factors) => ({
  mtls: $factors.filter((f) => f.type === 'mtls'),
  fido2: $factors.filter((f) => f.type === 'fido2'),
  piv: $factors.filter((f) => f.type === 'piv'),
}));

// ---- factor service bridge ------------------------------------------------

export const SecurityFactorService = {
  async list(userID: string): Promise<ListFactorsResponse | null> {
    return callBackend<ListFactorsResponse>('SecurityFactorService', 'ListFactors', userID);
  },

  async add(userID: string, req: AddFactorRequest): Promise<AddFactorResponse | null> {
    return callBackend<AddFactorResponse>('SecurityFactorService', 'AddFactor', userID, req);
  },

  async remove(userID: string, factorID: string): Promise<boolean> {
    try {
      await (window.go?.services as any)?.SecurityFactorService?.RemoveFactor(userID, factorID);
      return true;
    } catch {
      return false;
    }
  },

  async rotate(userID: string, req: RotateFactorRequest): Promise<AddFactorResponse | null> {
    return callBackend<AddFactorResponse>('SecurityFactorService', 'RotateFactor', userID, req);
  },

  async relabel(userID: string, factorID: string, label: string): Promise<boolean> {
    try {
      await (window.go?.services as any)?.SecurityFactorService?.RelabelFactor(userID, factorID, label);
      return true;
    } catch {
      return false;
    }
  },

  async setMFAPolicy(req: MFAPolicyRequest): Promise<boolean> {
    try {
      await (window.go?.services as any)?.SecurityFactorService?.SetMFAPolicy(req);
      return true;
    } catch {
      return false;
    }
  },

  async enumeratePIVCards(): Promise<PIVCardInfo[]> {
    const result = await callBackend<PIVCardInfo[]>('SecurityFactorService', 'EnumeratePIVCards');
    return result ?? [];
  },

  async readPIVCertPEM(slot: string): Promise<string | null> {
    return callBackend<string>('SecurityFactorService', 'ReadPIVCertPEM', slot);
  },
};

// ---- store actions --------------------------------------------------------

export async function loadFactors(userID: string): Promise<void> {
  factorState.update((s) => ({ ...s, loading: true, error: null }));
  const result = await SecurityFactorService.list(userID);
  if (!result) {
    factorState.update((s) => ({
      ...s,
      loading: false,
      error: 'Failed to load authentication factors',
    }));
    return;
  }
  factorState.update((s) => ({
    ...s,
    loading: false,
    factors: result.factors,
  }));
}

export function updateFactorLabel(factorID: string, label: string): void {
  factorState.update((s) => ({
    ...s,
    factors: s.factors.map((f) => (f.id === factorID ? { ...f, label } : f)),
  }));
}

export function markFactorRevoked(factorID: string): void {
  factorState.update((s) => ({
    ...s,
    factors: s.factors.map((f) =>
      f.id === factorID ? { ...f, revoked_at: new Date().toISOString() } : f
    ),
  }));
}

export function appendFactor(factor: AuthFactor): void {
  factorState.update((s) => ({ ...s, factors: [...s.factors, factor] }));
}
