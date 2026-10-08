// IPv4 address management inside the network CIDR.

export interface Cidr {
  base: number; // network address as uint32
  bits: number;
  text: string;
}

export function parseCidr(s: string): Cidr {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(s);
  if (!m) throw new Error(`invalid CIDR: ${s}`);
  const octets = m.slice(1, 5).map(Number);
  const bits = Number(m[5]);
  if (octets.some((o) => o > 255) || bits < 8 || bits > 30) throw new Error(`invalid CIDR: ${s}`);
  const addr = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const base = (addr & mask) >>> 0;
  return { base, bits, text: `${ipToString(base)}/${bits}` };
}

export function ipToString(n: number): string {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/**
 * Picks a free host address. Starts probing at a position derived from `seed`
 * (a hex hash of the device public key) so that concurrent enrollments, which
 * cannot see each other's writes, almost never pick the same address.
 */
export function allocate(cidr: Cidr, used: Set<string>, seedHex: string): string | null {
  const hosts = 2 ** (32 - cidr.bits) - 2; // exclude network and broadcast
  const start = parseInt(seedHex.slice(0, 8), 16) % hosts;
  for (let i = 0; i < hosts; i++) {
    const ip = ipToString(cidr.base + 1 + ((start + i) % hosts));
    if (!used.has(ip)) return ip;
  }
  return null;
}
