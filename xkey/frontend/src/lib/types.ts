/**
 * Shared type definitions for the xKey frontend.
 */

/** PIV smart card slot information */
export interface PIVSlot {
  slotId: string;
  label: string;
  purpose: string;
  loaded: boolean;
  algorithm: string | null;
  subject: string | null;
  issuer: string | null;
  serialNumber: string | null;
  notBefore: string | null;
  notAfter: string | null;
  keyUsage: string[];
  fingerprint: string | null;
  daysRemaining: number | null;
  backend: string | null;
  backendDisplayName: string | null;
}

/** TPM hardware information */
export interface TPMInfo {
  manufacturer: string;
  firmwareVersion: string;
  specVersion: string;
  family: string;
  level: number;
  revision: number;
  vendorId: string;
}

/** TPM identity key */
export interface TPMIdentityKey {
  id: string;
  label: string;
  algorithm: string;
  created: string;
  persistent: boolean;
  handleHex: string;
}

/** TPM PCR bank entry */
export interface PCREntry {
  index: number;
  value: string;
  description: string;
}

/** TPM PCR banks */
export interface PCRBank {
  algorithm: string;
  pcrs: PCREntry[];
}

/** Backend information */
export interface BackendInfo {
  name: string;
  available: boolean;
  keyCount: number;
  type: string;
}

/** Server status information */
export interface ServerStatus {
  url: string;
  running: boolean;
  uptime: string;
  version: string;
}

/** Audit log entry */
export interface AuditLogEntry {
  id: string;
  timestamp: string;
  operation: string;
  device: string;
  backend: string;
  keyId: string;
  success: boolean;
  details: string;
  ipAddress: string;
}
