import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";

// Shodan InternetDB — free, no API key (non-commercial use), data refreshed weekly.
// Docs: https://internetdb.shodan.io/
const limiter = new RateLimiter(500);
const cache = new TTLCache<any>(60 * 60 * 1000); // 1h

// ─── Types ───

export interface InternetDbResult {
  ip: string;
  found: boolean;
  ports: number[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
}

// ─── Host Lookup ───

export async function internetdbHost(ip: string): Promise<InternetDbResult> {
  const cached = cache.get(ip);
  if (cached) return cached;

  await limiter.acquire();
  const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);

  let result: InternetDbResult;
  if (res.status === 404) {
    // No data for the IP — not an error.
    result = { ip, found: false, ports: [], cpes: [], hostnames: [], tags: [], vulns: [] };
  } else if (!res.ok) {
    const detail = await res.json().then((d: any) => d?.detail).catch(() => undefined);
    throw new Error(`InternetDB lookup failed: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`);
  } else {
    const data = await res.json();
    result = {
      ip: data.ip ?? ip,
      found: true,
      ports: data.ports ?? [],
      cpes: data.cpes ?? [],
      hostnames: data.hostnames ?? [],
      tags: data.tags ?? [],
      vulns: [...(data.vulns ?? [])].sort(),
    };
  }

  cache.set(ip, result);
  return result;
}
