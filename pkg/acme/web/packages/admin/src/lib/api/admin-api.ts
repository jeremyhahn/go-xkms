/**
 * Admin-specific API calls for the CA administration interface.
 *
 * The admin server exposes routes under two prefixes:
 *   /admin/*             - Status, stats, certificates, accounts, orders
 *   /api/v1/tenants/*    - Tenant management, EAB, roles, users, CA operations
 */

import { apiClient } from '@trustedca/shared/api/client';
import type {
  CAStatus,
  CAStats,
  CertificateInfo,
  AccountInfo,
  OrderInfo,
  TenantInfo,
  TenantListResponse,
  TenantCAStatusInfo,
  TenantRootCAInfo,
  TenantIntCAInfo,
  EABInfo,
  CreateEABResponse,
  AuditLog,
  ApiResponse,
  ListCertificatesParams,
  ListAccountsParams,
  ListOrdersParams,
  ListEABParams,
  ListAuditLogsParams,
  CreateTenantRequest,
  UpdateTenantRequest,
  UpdateTenantStatusRequest,
  CreateTenantRootCARequest,
  CreateTenantIntermediateCARequest,
  UpdateTenantDefaultCARequest,
  UpdateIntermediateCAStatusRequest,
  CreateEABRequest,
  RevokeRequest,
} from '@trustedca/shared/api/types';

export const adminApi = {
  // =========================================================================
  // Status & Stats  (/admin/*)
  // =========================================================================
  getStatus: () =>
    apiClient.get<CAStatus>('/admin/status'),

  getStats: () =>
    apiClient.get<CAStats>('/admin/stats'),

  // =========================================================================
  // Certificates  (/admin/certificates/*)
  // =========================================================================
  listCertificates: (params?: ListCertificatesParams) =>
    apiClient.get<ApiResponse<CertificateInfo[]>>('/admin/certificates', params as Record<string, unknown>),

  getCertificate: (serial: string) =>
    apiClient.get<CertificateInfo>(`/admin/certificates/${serial}`),

  revokeCertificate: (serial: string, req: RevokeRequest) =>
    apiClient.post(`/admin/certificates/${serial}/revoke`, req),

  // =========================================================================
  // Accounts  (/admin/accounts/*)
  // =========================================================================
  listAccounts: (params?: ListAccountsParams) =>
    apiClient.get<ApiResponse<AccountInfo[]>>('/admin/accounts', params as Record<string, unknown>),

  getAccount: (id: string) =>
    apiClient.get<AccountInfo>(`/admin/accounts/${id}`),

  disableAccount: (id: string) =>
    apiClient.delete(`/admin/accounts/${id}`),

  // =========================================================================
  // Orders  (/admin/orders/*)
  // =========================================================================
  listOrders: (params?: ListOrdersParams) =>
    apiClient.get<ApiResponse<OrderInfo[]>>('/admin/orders', params as Record<string, unknown>),

  getOrder: (id: string) =>
    apiClient.get<OrderInfo>(`/admin/orders/${id}`),

  // =========================================================================
  // Tenants  (/api/v1/tenants/*)
  // =========================================================================
  // Create, list, get and delete are the core xkms tenant routes: the
  // collection keeps its trailing slash, pages by page_size, and a single
  // tenant comes wrapped as {tenant: ...}.
  listTenants: (params?: { page?: number; per_page?: number; status?: string }) =>
    apiClient.get<TenantListResponse>('/api/v1/tenants/', {
      page: params?.page,
      page_size: params?.per_page,
      status: params?.status,
    }),

  getTenant: async (id: string) =>
    (await apiClient.get<{ tenant: TenantInfo }>(`/api/v1/tenants/${id}`)).tenant,

  createTenant: async (req: CreateTenantRequest) =>
    (await apiClient.post<{ tenant: TenantInfo }>('/api/v1/tenants/', req)).tenant,

  updateTenant: (id: string, req: UpdateTenantRequest) =>
    apiClient.put<TenantInfo>(`/api/v1/tenants/${id}`, req),

  updateTenantStatus: (id: string, req: UpdateTenantStatusRequest) =>
    apiClient.put(`/api/v1/tenants/${id}/status`, req),

  deleteTenant: (id: string) =>
    apiClient.delete(`/api/v1/tenants/${id}`),

  // =========================================================================
  // Tenant CA  (/api/v1/tenants/{id}/*)
  // =========================================================================
  getTenantCAStatus: (tenantId: string) =>
    apiClient.get<TenantCAStatusInfo>(`/api/v1/tenants/${tenantId}/ca-status`),

  createTenantRootCA: (tenantId: string, req: CreateTenantRootCARequest) =>
    apiClient.post<TenantRootCAInfo>(`/api/v1/tenants/${tenantId}/root-ca`, req),

  createTenantIntermediateCA: (tenantId: string, req: CreateTenantIntermediateCARequest) =>
    apiClient.post<TenantIntCAInfo>(`/api/v1/tenants/${tenantId}/intermediate-cas`, req),

  updateTenantDefaultCA: (tenantId: string, req: UpdateTenantDefaultCARequest) =>
    apiClient.put(`/api/v1/tenants/${tenantId}/default-intermediate-ca`, req),

  updateIntermediateCAStatus: (tenantId: string, caId: string, req: UpdateIntermediateCAStatusRequest) =>
    apiClient.put(`/api/v1/tenants/${tenantId}/intermediate-cas/${caId}/status`, req),

  // =========================================================================
  // EAB  (/api/v1/tenants/{id}/eab/*)
  // =========================================================================
  listEABCredentials: (tenantId: string, params?: ListEABParams) =>
    apiClient.get<ApiResponse<EABInfo[]>>(`/api/v1/tenants/${tenantId}/eab`, params as Record<string, unknown>),

  createEABCredential: (tenantId: string, req: CreateEABRequest) =>
    apiClient.post<CreateEABResponse>(`/api/v1/tenants/${tenantId}/eab`, req),

  revokeEABCredential: (tenantId: string, eabId: string) =>
    apiClient.delete(`/api/v1/tenants/${tenantId}/eab/${eabId}`),

  // =========================================================================
  // Roles  (/api/v1/tenants/{id}/roles/*)
  // =========================================================================
  listRoles: (tenantId: string) =>
    apiClient.get<ApiResponse<any[]>>(`/api/v1/tenants/${tenantId}/roles`),

  createRole: (tenantId: string, req: { name: string; permissions?: string[] }) =>
    apiClient.post(`/api/v1/tenants/${tenantId}/roles`, req),

  getRole: (tenantId: string, roleId: string) =>
    apiClient.get(`/api/v1/tenants/${tenantId}/roles/${roleId}`),

  updateRole: (tenantId: string, roleId: string, req: { name?: string; permissions?: string[] }) =>
    apiClient.put(`/api/v1/tenants/${tenantId}/roles/${roleId}`, req),

  deleteRole: (tenantId: string, roleId: string) =>
    apiClient.delete(`/api/v1/tenants/${tenantId}/roles/${roleId}`),

  // =========================================================================
  // Users  (/api/v1/tenants/{id}/users/*)
  // =========================================================================
  listUsers: (tenantId: string) =>
    apiClient.get<ApiResponse<any[]>>(`/api/v1/tenants/${tenantId}/users`),

  createUser: (tenantId: string, req: { username: string; roleIDs?: string[] }) =>
    apiClient.post(`/api/v1/tenants/${tenantId}/users`, req),

  getUser: (tenantId: string, userId: string) =>
    apiClient.get(`/api/v1/tenants/${tenantId}/users/${userId}`),

  updateUser: (tenantId: string, userId: string, req: { username?: string; roleIDs?: string[] }) =>
    apiClient.put(`/api/v1/tenants/${tenantId}/users/${userId}`, req),

  deleteUser: (tenantId: string, userId: string) =>
    apiClient.delete(`/api/v1/tenants/${tenantId}/users/${userId}`),

  // =========================================================================
  // Audit  (/admin/audit/*)
  // =========================================================================
  listAuditLogs: (params?: ListAuditLogsParams) =>
    apiClient.get<ApiResponse<AuditLog[]>>('/admin/audit', params as Record<string, unknown>),
};
