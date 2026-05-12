/**
 * ACME client-specific API calls.
 *
 * The trusted-acme-client REST server mounts all client endpoints under
 * /api/v1/. Paths here include that prefix explicitly so the shared
 * ApiClient issues the request to the correct route.
 */

import { apiClient } from '@trustedca/shared/api/client';
import type {
  RegisterRequest,
  RegisterResponse,
  AddAccountRequest,
  AddAccountResponse,
  CertRequest,
  CertResponse,
  RenewRequest,
  RevokeClientRequest,
  EnrollRequest,
  EnrollResponse,
  AttestRequest,
  AttestResponse,
  ClientConfig,
  ClientConfigUpdate,
  RenewalStatus,
  RenewalConfig,
  RenewalConfigUpdate,
  AccountConfig,
  CertificateSpec,
  ManagedCertInfo,
} from '@trustedca/shared/api/types';

const API_V1 = '/api/v1';

export const clientApi = {
  // Account
  register: (req: RegisterRequest) =>
    apiClient.post<RegisterResponse>(`${API_V1}/account/register`, req),

  // Certificates
  requestCertificate: (req: CertRequest) =>
    apiClient.post<CertResponse>(`${API_V1}/certificate/request`, req),

  renewCertificate: (req: RenewRequest) =>
    apiClient.post<CertResponse>(`${API_V1}/certificate/renew`, req),

  revokeCertificate: (req: RevokeClientRequest) =>
    apiClient.post(`${API_V1}/certificate/revoke`, req),

  // Configuration
  getConfig: () =>
    apiClient.get<ClientConfig>(`${API_V1}/config`),

  updateConfig: (cfg: ClientConfigUpdate) =>
    apiClient.put(`${API_V1}/config`, cfg),

  // Device operations (TPM)
  deviceEnroll: (req: EnrollRequest) =>
    apiClient.post<EnrollResponse>(`${API_V1}/device/enroll`, req),

  deviceAttest: (req: AttestRequest) =>
    apiClient.post<AttestResponse>(`${API_V1}/device/attest`, req),

  // Auto-renewal
  getRenewalStatus: () =>
    apiClient.get<RenewalStatus>(`${API_V1}/renewal/status`),

  getRenewalConfig: () =>
    apiClient.get<RenewalConfig>(`${API_V1}/renewal/config`),

  updateRenewalConfig: (cfg: RenewalConfigUpdate) =>
    apiClient.put(`${API_V1}/renewal/config`, cfg),

  // Multi-account management
  listAccounts: () =>
    apiClient
      .get<{ accounts: Record<string, AccountConfig> } | Record<string, AccountConfig>>(`${API_V1}/accounts`)
      .then((d) => {
        if (d && typeof d === 'object' && 'accounts' in d) {
          return (d as { accounts: Record<string, AccountConfig> }).accounts;
        }
        return d as Record<string, AccountConfig>;
      }),

  getAccount: (name: string) =>
    apiClient.get<AccountConfig>(`${API_V1}/accounts/${name}`),

  addAccount: (req: AddAccountRequest) =>
    apiClient.post<AddAccountResponse>(`${API_V1}/accounts`, req),

  removeAccount: (name: string) =>
    apiClient.delete(`${API_V1}/accounts/${name}`),

  // Multi-account certificates
  listCertificates: (account?: string) =>
    apiClient
      .get<{ certificates: Record<string, CertificateSpec> } | Record<string, CertificateSpec>>(
        account ? `${API_V1}/certificates?account=${account}` : `${API_V1}/certificates`
      )
      .then((d) => {
        if (d && typeof d === 'object' && 'certificates' in d) {
          return (d as { certificates: Record<string, CertificateSpec> }).certificates;
        }
        return d as Record<string, CertificateSpec>;
      }),

  getCertificate: (name: string) =>
    apiClient.get<ManagedCertInfo>(`${API_V1}/certificates/${name}`),

  deployCertificate: (name: string) =>
    apiClient.post(`${API_V1}/certificates/${name}/deploy`),
};
