const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const V4 = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);

const V4_BOGONS: [number, number][] = [
  [0x00000000, 8], [0x0a000000, 8], [0x64400000, 10], [0x7f000000, 8], [0xa9fe0000, 16], [0xac100000, 12],
  [0xc0000000, 24], [0xc0000200, 24], [0xc0a80000, 16], [0xc6120000, 15], [0xc6336400, 24], [0xcb007100, 24],
  [0xe0000000, 3],
];

export function publicV4(addr: string): boolean {
  const n = addr.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
  return !V4_BOGONS.some(([net, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(net / 2 ** (32 - bits)));
}

// Global unicast 2000::/3 only, minus documentation space; this also rules out ::, ::1, v4-mapped, ULA, link-local and multicast.
export function publicV6(addr: string): boolean {
  if (addr.startsWith(":")) return false;
  const first = parseInt(addr.split(":")[0], 16);
  return first >= 0x2000 && first <= 0x3fff && !/^2001:0*db8(?::|$)/i.test(addr);
}

export interface Addr {
  family: 4 | 6;
  // As written in the feed files: a bare IPv4 address or an IPv6 /64.
  value: string;
  // The canonical /ip/<slug> path segment.
  slug: string;
}

function expandV6(host: string): string[] {
  const [head, tail] = host.split("::");
  const left = head ? head.split(":") : [];
  const right = tail === undefined ? [] : tail ? tail.split(":") : [];
  return [...left, ...Array(8 - left.length - right.length).fill("0"), ...right];
}

const v6Host = (addr: string): string | null => {
  try {
    return new URL(`http://[${addr}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
};

const slash64 = (host: string) => v6Host([...expandV6(host).slice(0, 4), "0", "0", "0", "0"].join(":"))!;

export function parseAddr(raw: string): Addr | null {
  const input = raw.trim();
  if (!input || input.length > 64 || !/^[0-9A-Fa-f:./]+$/.test(input)) return null;
  const [addr, prefix, ...rest] = input.split("/");
  if (rest.length) return null;
  if (V4.test(addr)) return prefix === undefined && publicV4(addr) ? { family: 4, value: addr, slug: addr } : null;
  if ((prefix !== undefined && prefix !== "64") || !addr.includes(":") || addr.includes(".")) return null;
  const host = v6Host(addr);
  if (host === null) return null;
  const net = slash64(host);
  return publicV6(net) ? { family: 6, value: `${net}/64`, slug: net } : null;
}

// One rate-limit bucket per IPv6 /64: a single host can rotate through its whole /64.
export function limitKey(clientIp: string): string {
  const host = clientIp.includes(":") ? v6Host(clientIp) : null;
  return host === null ? clientIp : `${slash64(host)}/64`;
}
