/**
 * Classifying IP addresses a resolver must not connect to.
 *
 * This works on parsed addresses rather than on hostname text, because the
 * text a counterparty controls (a DNS name, `0177.0.0.1`, `::ffff:7f00:1`) says
 * little about where a connection would actually land.
 */

import { isIP } from 'node:net';

/** IPv4 ranges that are never a legitimate public counterparty: [network, prefix length]. */
const BLOCKED_V4: readonly (readonly [string, number])[] = [
  ['0.0.0.0', 8], // "this network"
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // carrier-grade NAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, including cloud metadata at 169.254.169.254
  ['172.16.0.0', 12], // RFC 1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, including broadcast
];

function v4ToNumber(address: string): number {
  const octets = address.split('.').map(Number);
  return (
    (((octets[0] ?? 0) << 24) | ((octets[1] ?? 0) << 16) | ((octets[2] ?? 0) << 8) | (octets[3] ?? 0)) >>> 0
  );
}

function isBlockedV4(address: string): boolean {
  const value = v4ToNumber(address);
  return BLOCKED_V4.some(([network, prefix]) => {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (value & mask) >>> 0 === (v4ToNumber(network) & mask) >>> 0;
  });
}

/** Expand any IPv6 text form to 8 numeric groups, via the URL parser's normalisation. */
function v6Groups(address: string): number[] | undefined {
  let normalised: string;
  try {
    normalised = new URL(`http://[${address}]/`).hostname.slice(1, -1);
  } catch {
    return undefined;
  }
  const [head = '', tail] = normalised.split('::');
  const left = head === '' ? [] : head.split(':');
  const right = tail === undefined || tail === '' ? [] : tail.split(':');
  const fill = tail === undefined ? 0 : 8 - left.length - right.length;
  const groups = [...left, ...Array<string>(fill).fill('0'), ...right].map((group) => parseInt(group, 16));
  return groups.length === 8 && groups.every((group) => Number.isInteger(group)) ? groups : undefined;
}

const embeddedV4 = (high: number, low: number): string =>
  `${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`;

function isBlockedV6(address: string): boolean {
  const g = v6Groups(address);
  if (!g) return true; // unparseable: refuse rather than guess

  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = g;
  const firstFiveZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;

  // :: (unspecified), ::1 (loopback), and the deprecated IPv4-compatible ::a.b.c.d.
  if (firstFiveZero && g5 === 0) return true;
  // ::ffff:a.b.c.d (IPv4-mapped): the connection goes to the embedded IPv4 address.
  if (firstFiveZero && g5 === 0xffff) return isBlockedV4(embeddedV4(g6, g7));
  // 64:ff9b::/96 (NAT64): same, the IPv4 address is what is reached.
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return isBlockedV4(embeddedV4(g6, g7));
  }
  // 2002::/16 (6to4) embeds an IPv4 address in the next 32 bits.
  if (g0 === 0x2002) return isBlockedV4(embeddedV4(g1, g2));

  // Fail closed: only global unicast (2000::/3) is a candidate, which refuses
  // every other special-purpose block, including 64:ff9b:1::/48, ::ffff:0:0:0/96,
  // 100::/64, fc00::/7, fe80::/10 and ff00::/8, without listing each of them.
  if ((g0 & 0xe000) !== 0x2000) return true;
  // Special-purpose blocks inside 2000::/3.
  if (g0 === 0x2001 && g1 < 0x0200) return true; // 2001::/23: Teredo, benchmarking, ORCHID and other protocol assignments
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
  if (g0 === 0x3fff && g1 < 0x1000) return true; // 3fff::/20 documentation
  return false;
}

/**
 * True when `address` is an IP literal in a loopback, link-local, private,
 * reserved or otherwise non-public range. Anything that is not an IP literal
 * returns `false`: this classifies addresses, it does not resolve names.
 */
export function isPrivateAddress(address: string): boolean {
  const bare = address.startsWith('[') && address.endsWith(']') ? address.slice(1, -1) : address;
  const zoneless = bare.split('%')[0] ?? bare;
  switch (isIP(zoneless)) {
    case 4:
      return isBlockedV4(zoneless);
    case 6:
      return isBlockedV6(zoneless);
    default:
      return false;
  }
}
