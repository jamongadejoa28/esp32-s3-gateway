// IPv4 helpers for client-side validation (the gateway re-validates everything).
const RE = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

export const isIp = (s) => RE.test(s);

/** Dotted quad -> uint32, or null. */
export function ipNum(s) {
  if (!isIp(s)) return null;
  return s.split('.').reduce((a, x) => ((a << 8) | Number(x)) >>> 0, 0);
}

/** True for a contiguous, non-zero netmask. */
export function isMask(s) {
  const m = ipNum(s);
  if (m === null || m === 0) return false;
  const inv = ~m >>> 0;
  return (inv & (inv + 1)) === 0;
}

export function prefixOf(mask) {
  let m = ipNum(mask);
  let n = 0;
  while (m & 0x80000000) { n++; m = (m << 1) >>> 0; }
  return n;
}

const maskOf = (bits) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);

/** "a.b.c.d/n" (bare address = /32) with host bits zero -> {net, bits}, else null. */
export function parseCidr(s) {
  const m = /^([\d.]+)(?:\/(\d{1,2}))?$/.exec(String(s).trim());
  if (!m || !isIp(m[1])) return null;
  const bits = m[2] === undefined ? 32 : Number(m[2]);
  if (bits > 32) return null;
  const net = ipNum(m[1]);
  if ((net & ~maskOf(bits)) >>> 0) return null;
  return { net, bits };
}

/** True when the two networks (ip/mask) overlap. */
export function overlaps(ipA, maskA, ipB, maskB) {
  const a = ipNum(ipA);
  const b = ipNum(ipB);
  const m = (ipNum(maskA) & ipNum(maskB)) >>> 0;
  return ((a & m) >>> 0) === ((b & m) >>> 0);
}

export const sameSubnet = (ip, gw, mask) => ((ipNum(ip) & ipNum(mask)) >>> 0) === ((ipNum(gw) & ipNum(mask)) >>> 0);

export const AP_NET = '192.168.150.0';
export const AP_MASK = '255.255.255.0';
