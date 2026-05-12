/**
 * Vendor badge resolution — mirrors the logic in the web UI's
 * src/types/auth-factors.ts so both GUIs display the same vendor names.
 *
 * AAGUID → vendor name subset (full list from FIDO MDS).
 */

export interface VendorBadge {
  name: string;
  aaguid?: string;
}

export type AuthFactorType = 'mtls' | 'fido2' | 'piv';

export interface AuthFactor {
  id: string;
  type: AuthFactorType;
  label: string;
  metadata: Record<string, string>;
  registered_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

const KNOWN_AAGUIDS: Record<string, string> = {
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 Series',
  'cb69481e-8ff7-4039-93ec-0a2729a154a8': 'YubiKey 5 NFC',
  'f8a011f3-8c0a-4d15-8006-17111f9edc7d': 'Security Key by Yubico',
  'b92c3f9a-c014-4056-887f-140a2501163b': 'Security Key 2 NFC',
  'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5Ci',
  '149a2021-8ef6-4133-96b8-81f8d5b7f1f5': 'Solo Tap 2',
  '8876631b-d4a0-427f-5773-0ec71c9e0279': 'Nitrokey FIDO2',
  '12ded745-4bed-47d4-abaa-e713f51d6393': 'Nitrokey 3',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'ChromeOS (Google)',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
};

export function vendorFromAAGUID(aaguid: string): VendorBadge | null {
  const name = KNOWN_AAGUIDS[aaguid.toLowerCase()];
  if (!name) return null;
  return { name, aaguid };
}

export function vendorFromPIVCert(subject: string, serial?: string): VendorBadge {
  const lc = subject.toLowerCase();
  if (lc.includes('yubico') || lc.includes('yubikey')) return { name: 'YubiKey PIV' };
  if (lc.includes('nitrokey')) return { name: 'Nitrokey PIV' };
  if (lc.includes('goldkey')) return { name: 'GoldKey PIV' };
  return { name: subject || (serial ? `Card ${serial.slice(-6)}` : 'PIV Card') };
}

export function resolveVendorBadge(factor: AuthFactor): VendorBadge {
  switch (factor.type) {
    case 'fido2': {
      const aaguid = factor.metadata?.['aaguid'] ?? '';
      const resolved = aaguid ? vendorFromAAGUID(aaguid) : null;
      return resolved ?? { name: factor.metadata?.['vendor'] ?? 'FIDO2 Key' };
    }
    case 'piv': {
      const subject = factor.metadata?.['cert_subject'] ?? '';
      const serial = factor.metadata?.['card_serial'] ?? '';
      return vendorFromPIVCert(subject, serial);
    }
    case 'mtls': {
      const issuer = factor.metadata?.['issuer_cn'];
      return { name: issuer ?? 'Self-issued (mTLS)' };
    }
  }
}
