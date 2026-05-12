import { writable } from 'svelte/store';
import type { CertificateInfo, ListCertificatesParams, Pagination } from '@trustedca/shared/api/types';
import { adminApi } from '../api/admin-api';
import { notifyError } from '@trustedca/shared/stores/notifications';

export const certificates = writable<CertificateInfo[]>([]);
export const certsPagination = writable<Pagination | null>(null);
export const certsLoading = writable(false);

export async function fetchCertificates(params?: ListCertificatesParams): Promise<void> {
  certsLoading.set(true);
  try {
    const res = await adminApi.listCertificates(params) as any;
    certificates.set(res.items ?? res.data ?? []);
    certsPagination.set(res.pagination ?? { page: res.page ?? 1, per_page: res.per_page ?? 20, total: res.total ?? 0 });
  } catch (e) {
    notifyError(`Failed to fetch certificates: ${(e as Error).message}`);
  } finally {
    certsLoading.set(false);
  }
}
