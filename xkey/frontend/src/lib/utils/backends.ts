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
