import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";
import { comparePriority } from "../cvedb/index.js";

const limiter = new RateLimiter(1000); // 1 req/s
const cache = new TTLCache<any>(5 * 60 * 1000); // 5 min

// Throw a consistent error for a failed Shodan response, appending the API's own
// error message (e.g. "Invalid API key", "No information available") when present.
async function shodanError(res: Response, action: string): Promise<Error> {
  const apiError = await res.json().then((d: any) => d?.error).catch(() => undefined);
  return new Error(`Shodan ${action} failed: ${res.status} ${res.statusText}${apiError ? ` — ${apiError}` : ""}`);
}

// ─── Types ───

export interface ShodanVuln {
  cve: string;
  cvss?: number;
  epss?: number;
  kev?: boolean;
  /** true = confirmed by Shodan; false = inferred from the software version (may be a false positive) */
  verified: boolean;
  summary?: string;
}

interface ShodanService {
  port: number;
  transport: string;
  module?: string;
  product?: string;
  version?: string;
  cpe?: string[];
  tags?: string[];
  timestamp?: string;
  vulns?: ShodanVuln[];
  ssl?: {
    versions: string[];
    cipher?: string;
    certSubject?: string;
    certIssuer?: string;
    certExpires?: string;
    certExpired?: boolean;
  };
  http?: {
    status?: number;
    title?: string;
    server?: string;
    components?: string[];
    waf?: string;
  };
  banner?: string;
}

interface ShodanHostVuln extends ShodanVuln {
  ports: number[];
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
  /** CVE IDs sorted by priority (KEV, EPSS, CVSS) */
  vulns: string[];
  vulnSummary: { total: number; verified: number; kev: number; critical: number; high: number };
  vulnDetails: ShodanHostVuln[];
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
  version?: string;
  os?: string;
  asn?: string;
  domains: string[];
  cpe?: string[];
  tags?: string[];
  vulns?: string[];
  timestamp?: string;
}

interface ShodanSearchResult {
  total: number;
  matches: ShodanSearchMatch[];
  facets?: Record<string, { value: string; count: number }[]>;
}

interface ShodanCountResult {
  query: string;
  total: number;
  facets: Record<string, { value: string; count: number }[]>;
}

interface ShodanExploitResult {
  total: number;
  matches: { title: string; source: string; type?: string; author?: string; date?: string; cve?: string[] }[];
}

// ─── Helpers ───

function normalizeVulns(raw: any): ShodanVuln[] | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  // Banner-level vulns are an object keyed by CVE ID; host-level `vulns` is a plain string[].
  const entries: [string, any][] = Array.isArray(raw) ? raw.map((id: string) => [id, {}]) : Object.entries(raw);
  if (entries.length === 0) return undefined;
  return entries.map(([cve, v]) => ({
    cve,
    cvss: typeof v?.cvss === "number" ? v.cvss : v?.cvss != null ? Number(v.cvss) : undefined,
    epss: v?.epss ?? undefined,
    kev: v?.kev ?? undefined,
    verified: v?.verified === true,
    summary: v?.summary ?? undefined,
  }));
}

function sslVersionsSupported(versions: unknown): string[] {
  // Shodan lists unsupported versions with a leading "-" (e.g. "-SSLv3").
  return Array.isArray(versions) ? versions.filter((v) => typeof v === "string" && !v.startsWith("-")) : [];
}

function normalizeService(s: any): ShodanService {
  const ssl = s.ssl;
  const http = s.http;
  return {
    port: s.port,
    transport: s.transport ?? "tcp",
    module: s._shodan?.module,
    product: s.product,
    version: s.version,
    cpe: s.cpe23 ?? s.cpe,
    tags: s.tags?.length ? s.tags : undefined,
    timestamp: s.timestamp,
    vulns: normalizeVulns(s.vulns),
    ssl: ssl
      ? {
          versions: sslVersionsSupported(ssl.versions),
          cipher: ssl.cipher?.name,
          certSubject: ssl.cert?.subject?.CN,
          certIssuer: ssl.cert?.issuer?.CN ?? ssl.cert?.issuer?.O,
          certExpires: ssl.cert?.expires,
          certExpired: ssl.cert?.expired,
        }
      : undefined,
    http: http
      ? {
          status: http.status,
          title: http.title ?? undefined,
          server: http.server ?? undefined,
          components: http.components ? Object.keys(http.components) : undefined,
          waf: http.waf ?? undefined,
        }
      : undefined,
    banner: s.data ? String(s.data).slice(0, 500) : undefined,
  };
}

function facetsToList(facets: any): Record<string, { value: string; count: number }[]> {
  const out: Record<string, { value: string; count: number }[]> = {};
  for (const [name, buckets] of Object.entries(facets ?? {})) {
    out[name] = ((buckets as any[]) ?? []).map((b) => ({ value: String(b.value), count: b.count }));
  }
  return out;
}

// ─── Host Details ───

export async function shodanHost(ip: string, apiKey: string, history = false): Promise<ShodanHostResult> {
  const cacheKey = `host:${ip}:${history}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  await limiter.acquire();
  const params = new URLSearchParams({ key: apiKey });
  if (history) params.set("history", "true");
  const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?${params}`);
  if (res.status === 404) {
    // Shodan returns 404 when it simply has no scan data for the IP — not a failure.
    throw new Error(`Shodan has no information for ${ip} (the host has not been indexed by Shodan).`);
  }
  if (!res.ok) throw await shodanError(res, "host lookup");
  const data = await res.json();

  const services: ShodanService[] = (data.data ?? []).map(normalizeService);

  // Merge banner-level vulns (which carry CVSS/EPSS/KEV/verified) across services.
  const byCve = new Map<string, ShodanHostVuln>();
  for (const svc of services) {
    for (const v of svc.vulns ?? []) {
      const existing = byCve.get(v.cve);
      if (existing) {
        if (!existing.ports.includes(svc.port)) existing.ports.push(svc.port);
        existing.verified ||= v.verified;
      } else {
        byCve.set(v.cve, { ...v, ports: [svc.port] });
      }
    }
  }
  // Host-level list may contain IDs not attached to any banner.
  for (const v of normalizeVulns(data.vulns) ?? []) {
    if (!byCve.has(v.cve)) byCve.set(v.cve, { ...v, ports: [] });
  }
  const vulnDetails = [...byCve.values()].sort(comparePriority);

  const result: ShodanHostResult = {
    ip: data.ip_str ?? ip,
    hostnames: data.hostnames ?? [],
    org: data.org,
    isp: data.isp,
    os: data.os,
    asn: data.asn,
    country: data.country_name,
    city: data.city,
    vulns: vulnDetails.map((v) => v.cve),
    vulnSummary: {
      total: vulnDetails.length,
      verified: vulnDetails.filter((v) => v.verified).length,
      kev: vulnDetails.filter((v) => v.kev).length,
      critical: vulnDetails.filter((v) => (v.cvss ?? 0) >= 9).length,
      high: vulnDetails.filter((v) => (v.cvss ?? 0) >= 7 && (v.cvss ?? 0) < 9).length,
    },
    vulnDetails,
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
      version: m.version,
      os: m.os,
      asn: m.asn,
      domains: m.domains ?? [],
      cpe: m.cpe23 ?? m.cpe,
      tags: m.tags?.length ? m.tags : undefined,
      vulns: m.vulns ? Object.keys(m.vulns) : undefined,
      timestamp: m.timestamp,
    })),
    facets: data.facets ? facetsToList(data.facets) : undefined,
  };
}

// ─── Count (no query credits) ───

export async function shodanCount(query: string, apiKey: string, facets?: string): Promise<ShodanCountResult> {
  await limiter.acquire();
  const params = new URLSearchParams({ key: apiKey, query });
  if (facets) params.set("facets", facets);

  const res = await fetch(`https://api.shodan.io/shodan/host/count?${params}`);
  if (!res.ok) throw await shodanError(res, "count");
  const data = await res.json();

  return { query, total: data.total ?? 0, facets: facetsToList(data.facets) };
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
