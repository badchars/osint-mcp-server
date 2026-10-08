import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";

const limiter = new RateLimiter(1000); // 1 req/s
const cache = new TTLCache<any>(5 * 60 * 1000); // 5 min

// Throw a consistent error for a failed Shodan response, appending the API's own
// error message (e.g. "Invalid API key", "No information available") when present.
async function shodanError(res: Response, action: string): Promise<Error> {
  const apiError = await res.json().then((d: any) => d?.error).catch(() => undefined);
  return new Error(`Shodan ${action} failed: ${res.status} ${res.statusText}${apiError ? ` — ${apiError}` : ""}`);
}

// ─── Types ───

interface ShodanService {
  port: number;
  transport: string;
  product?: string;
  version?: string;
  cpe?: string[];
  banner?: string;
}

interface ShodanHostResult {
  ip: string;
  hostnames: string[];
  org?: string;
  isp?: string;
  os?: string;
  asn?: string;
  country?: string;
  city?: string;
  vulns?: string[];
  ports: number[];
  services: ShodanService[];
  lastUpdate?: string;
  tags?: string[];
}

interface ShodanSearchMatch {
  ip_str: string;
  port: number;
  org?: string;
  hostnames: string[];
  product?: string;
  os?: string;
  asn?: string;
  domains: string[];
}

interface ShodanSearchResult {
  total: number;
  matches: ShodanSearchMatch[];
  facets?: Record<string, [string, number][]>;
}

interface ShodanExploitResult {
  total: number;
  matches: { title: string; source: string; type?: string; author?: string; date?: string; cve?: string[] }[];
}

// ─── Host Details ───

export async function shodanHost(ip: string, apiKey: string): Promise<ShodanHostResult> {
  const cacheKey = `host:${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  await limiter.acquire();
  const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`);
  if (res.status === 404) {
    // Shodan returns 404 when it simply has no scan data for the IP — not a failure.
    throw new Error(`Shodan has no information for ${ip} (the host has not been indexed by Shodan).`);
  }
  if (!res.ok) throw await shodanError(res, "host lookup");
  const data = await res.json();

  const services: ShodanService[] = (data.data ?? []).map((s: any) => ({
    port: s.port,
    transport: s.transport ?? "tcp",
    product: s.product,
    version: s.version,
    cpe: s.cpe,
    banner: s.data ? String(s.data).slice(0, 500) : undefined,
  }));

  const result: ShodanHostResult = {
    ip: data.ip_str ?? ip,
    hostnames: data.hostnames ?? [],
    org: data.org,
    isp: data.isp,
    os: data.os,
    asn: data.asn,
    country: data.country_name,
    city: data.city,
    vulns: data.vulns,
    ports: data.ports ?? [],
    services,
    lastUpdate: data.last_update,
    tags: data.tags,
  };

  cache.set(cacheKey, result);
  return result;
}

// ─── Search ───

export async function shodanSearch(query: string, apiKey: string, page = 1, facets?: string): Promise<ShodanSearchResult> {
  await limiter.acquire();
  const params = new URLSearchParams({ key: apiKey, query, page: String(page) });
  if (facets) params.set("facets", facets);

  const res = await fetch(`https://api.shodan.io/shodan/host/search?${params}`);
  if (!res.ok) throw await shodanError(res, "search");
  const data = await res.json();

  return {
    total: data.total ?? 0,
    matches: (data.matches ?? []).map((m: any) => ({
      ip_str: m.ip_str,
      port: m.port,
      org: m.org,
      hostnames: m.hostnames ?? [],
      product: m.product,
      os: m.os,
      asn: m.asn,
      domains: m.domains ?? [],
    })),
    facets: data.facets,
  };
}

// ─── DNS Resolve ───

export async function shodanDnsResolve(hostnames: string[], apiKey: string): Promise<Record<string, string | null>> {
  await limiter.acquire();
  const csv = hostnames.join(",");
  const res = await fetch(`https://api.shodan.io/dns/resolve?hostnames=${encodeURIComponent(csv)}&key=${apiKey}`);
  if (!res.ok) throw await shodanError(res, "DNS resolve");
  return res.json();
}

// ─── Exploit Search ───

export async function shodanExploits(query: string, apiKey: string, type?: string): Promise<ShodanExploitResult> {
  await limiter.acquire();
  const params = new URLSearchParams({ query, key: apiKey });
  if (type) params.set("type", type);

  const res = await fetch(`https://exploits.shodan.io/api/search?${params}`);
  if (!res.ok) throw await shodanError(res, "exploit search");
  const data = await res.json();

  return {
    total: data.total ?? 0,
    matches: (data.matches ?? []).map((m: any) => ({
      title: m.description ?? m.title ?? "",
      source: m.source ?? "",
      type: m.type,
      author: m.author,
      date: m.date,
      cve: m.cve,
    })),
  };
}
