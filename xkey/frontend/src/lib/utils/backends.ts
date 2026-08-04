import {
  mdiKey,
  mdiChip,
  mdiShieldCheckOutline,
  mdiCellphone,
  mdiCloudOutline,
} from '$lib/utils/icons';

export interface BackendMeta {
  label: string;
  icon: string;
  hardware: boolean;
}

export const backendMeta: Record<string, BackendMeta> = {
  software: { label: 'Software', icon: mdiKey, hardware: false },
  tpm2: { label: 'TPM 2.0', icon: mdiChip, hardware: true },
  pkcs11: { label: 'PKCS#11', icon: mdiShieldCheckOutline, hardware: true },
  phone: { label: 'Phone', icon: mdiCellphone, hardware: true },
  awskms: { label: 'AWS KMS', icon: mdiCloudOutline, hardware: false },
  gcpkms: { label: 'GCP KMS', icon: mdiCloudOutline, hardware: false },
  azurekv: { label: 'Azure Key Vault', icon: mdiCloudOutline, hardware: false },
  vault: { label: 'HashiCorp Vault', icon: mdiCloudOutline, hardware: false },
};

export function getBackendLabel(backend: string): string {
  return backendMeta[backend]?.label ?? backend;
}

export function getBackendIcon(backend: string): string {
  return backendMeta[backend]?.icon ?? mdiKey;
}

export function isHardwareBackend(backend: string): boolean {
  return backendMeta[backend]?.hardware ?? false;
}

export interface BackendColor {
  bg: string;
  fg: string;
}

/**
 * Per-backend badge colors — the single source of truth for backend coloring
 * across the app (previously duplicated inline in several views). Cloud KMS
 * backends share one palette; unknown backends fall back to a neutral surface.
 */
const backendColors: Record<string, BackendColor> = {
  software: { bg: 'var(--color-secondary-container)', fg: 'var(--color-on-secondary-container)' },
  tpm2: { bg: 'var(--color-primary-container)', fg: 'var(--color-on-primary-container)' },
  pkcs11: {
    bg: 'var(--color-tertiary-container, #f3e8fd)',
    fg: 'var(--color-on-tertiary-container, #4a1e73)',
  },
  phone: { bg: '#fff3cd', fg: '#856404' },
  awskms: { bg: '#d4edda', fg: '#155724' },
  gcpkms: { bg: '#d4edda', fg: '#155724' },
  azurekv: { bg: '#cce5ff', fg: '#004085' },
  vault: { bg: 'var(--color-surface-container)', fg: 'var(--color-on-surface-variant)' },
};

const neutralBackendColor: BackendColor = {
  bg: 'var(--color-surface-container-high, var(--color-surface-container))',
  fg: 'var(--color-on-surface-variant)',
};

/** getBackendColor returns the badge palette for a backend id. */
export function getBackendColor(backend: string): BackendColor {
  return backendColors[backend] ?? neutralBackendColor;
}
