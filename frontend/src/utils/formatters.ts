/**
 * Formatting utilities for IPsec Analyzer
 * Resolves Bug 5 (UTC date-time formatting) and Bug 4 (Vendor ID parsing)
 */

export function formatUtcDateTime(epochSeconds: number | string | null | undefined): string {
  if (epochSeconds === null || epochSeconds === undefined || epochSeconds === '') {
    return '-';
  }
  const sec = typeof epochSeconds === 'string' ? parseFloat(epochSeconds) : epochSeconds;
  if (isNaN(sec) || sec <= 0) {
    return '-';
  }

  // Date takes milliseconds
  const date = new Date(sec * 1000);
  if (isNaN(date.getTime())) {
    return '-';
  }

  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  const h = String(date.getUTCHours()).padStart(2, '0');
  const min = String(date.getUTCMinutes()).padStart(2, '0');
  const s = String(date.getUTCSeconds()).padStart(2, '0');

  return `${y}-${m}-${d} ${h}:${min}:${s} UTC`;
}

export interface DecodedVendorId {
  raw_hex: string;
  name?: string | null;
  ascii_decoded?: string | null;
  display: string;
  category?: string;
  label: string;
}

export function parseVendorId(raw: any): DecodedVendorId {
  if (!raw) {
    return {
      raw_hex: '',
      display: 'Unknown',
      label: 'peer-reported (may be spoofed)',
    };
  }

  if (typeof raw === 'object' && raw.raw_hex) {
    return {
      raw_hex: raw.raw_hex,
      name: raw.name,
      ascii_decoded: raw.ascii_decoded,
      display: raw.display || raw.name || raw.ascii_decoded || raw.raw_hex,
      category: raw.category,
      label: raw.label || 'peer-reported (may be spoofed)',
    };
  }

  const hexStr = String(raw).trim().toLowerCase();

  // Known VIDs
  const knownMap: Record<string, string> = {
    '4048b7d56ebce88525e7de7f00d6c2d3': 'IKE Fragmentation',
    '882fe56d6fd20dbc2251613b2ebe5beb': 'strongSwan',
    'afcad71368a1f1c96b8696fc77570100': 'RFC 3706 (Dead Peer Detection - DPD)',
    '09002689dfd6b712': 'XAUTH',
    '12f5f28c457168a9702d9fe274cc0100': 'Cisco Unity',
    '1e2b516905991c7d7c96fcbfb587e461': 'Microsoft Windows (IKEv1)',
    'fb1d30ef54456c22d45987f9f32292ce': 'Microsoft Windows (IKEv2)',
    'f4487641304a2220a2be2d16711e247f': 'Check Point',
    '404bf4cb61341edc65ab22618b679f50': 'SonicWALL',
    '8299031420b91eb0125e313f8fe8a328': 'Fortinet',
  };

  if (knownMap[hexStr]) {
    return {
      raw_hex: hexStr,
      name: knownMap[hexStr],
      display: knownMap[hexStr],
      category: 'Feature / Vendor',
      label: 'peer-reported (may be spoofed)',
    };
  }

  // Attempt ASCII decode
  try {
    let ascii = '';
    for (let i = 0; i < hexStr.length; i += 2) {
      const code = parseInt(hexStr.substring(i, i + 2), 16);
      if (code >= 32 && code <= 126) {
        ascii += String.fromCharCode(code);
      } else {
        ascii = '';
        break;
      }
    }
    if (ascii.length >= 2) {
      return {
        raw_hex: hexStr,
        ascii_decoded: ascii,
        display: ascii,
        category: 'ASCII String',
        label: 'peer-reported (may be spoofed)',
      };
    }
  } catch {
    // ignore
  }

  return {
    raw_hex: hexStr,
    display: hexStr,
    category: 'Vendor Hash',
    label: 'peer-reported (may be spoofed)',
  };
}
