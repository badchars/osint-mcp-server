import { RateLimiter } from "../utils/rate-limiter.js";
import { TTLCache } from "../utils/cache.js";

// Shodan CVEDB — free, no API key (non-commercial use). Docs: https://cvedb.shodan.io/docs
const CVEDB_BASE = "https://cvedb.shodan.io";

const limiter = new RateLimiter(250);
const cache = new TTLCache<any>(60 * 60 * 1000); // 1h — EPSS/KEV update daily

// ─── Types ───

export interface CveSummary {
  id: string;
  summary: string;
  cvss?: number;
  cvssVersion?: number;
  epss?: number;
  rankingEpss?: number;
  kev: boolean;
  ransomwareCampaign?: string;
  publishedTime?: string;
}

interface CveDetails extends CveSummary {
  cvssV2?: number;
  cvssV3?: number;
  cvssV4?: number;
  proposeAction?: string;
  references: string[];
  cpes: string[];
  cpeCount: number;
  euvdId?: string;
}

interface CveSearchResult {
  query: Record<string, string>;
  total: number;
  cves: CveSummary[];
}

export interface CveSearchOptions {
  cpe23?: string;
  product?: string;
  kevOnly?: boolean;
  sortByEpss?: boolean;
  startDate?: string;
  endDate?: string;
  limit?: number;
}

// ─── Helpers ───

const CPE23_WITH_VERSION = /^cpe:2\.3:[aho]:[^:]+:[^:]+:[^:]+/;

/**
 * Convert a CPE 2.2 URI (`cpe:/a:apache:http_server:2.4.7`, as returned by InternetDB)
 * to CPE 2.3 (`cpe:2.3:a:apache:http_server:2.4.7`). Returns undefined when the CPE
 * has no version — CVEDB rejects version-less CPEs.
 */
export function toCpe23(cpe: string): string | undefined {
  let c = cpe.trim();
  if (c.startsWith("cpe:/")) c = `cpe:2.3:${c.slice(5)}`;
  if (!CPE23_WITH_VERSION.test(c)) return undefined;
  const version = c.split(":")[5];
  return version && version !== "*" && version !== "-" ? c : undefined;
}

async function cvedbFetch(path: string): Promise<any | null> {
  const cached = cache.get(path);
  if (cached !== undefined) return cached;

  await limiter.acquire();
  const res = await fetch(`${CVEDB_BASE}${path}`, { headers: { Accept: "application/json" } });
  if (res.status === 404) {
    cache.set(path, null);
    return null;
  }
  if (!res.ok) {
    const detail = await res.json().then((d: any) => (typeof d?.detail === "string" ? d.detail : JSON.stringify(d?.detail))).catch(() => undefined);
    throw new Error(`Shodan CVEDB error: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}`);
  }
  const data = await res.json();
  cache.set(path, data);
  return data;
}

function normalizeSummary(c: any): CveSummary {
  return {
    id: c.cve_id,
    summary: c.summary ?? "",
    cvss: c.cvss ?? undefined,
    cvssVersion: c.cvss_version ?? undefined,
    epss: c.epss ?? undefined,
    rankingEpss: c.ranking_epss ?? undefined,
    kev: c.kev === true,
    ransomwareCampaign: c.ransomware_campaign ?? undefined,
    publishedTime: c.published_time ?? undefined,
  };
}

/** Sort comparator: KEV first, then EPSS, then CVSS (all descending). */
export function comparePriority(
  a: { kev?: boolean; epss?: number; cvss?: number },
  b: { kev?: boolean; epss?: number; cvss?: number },
): number {
  return (
    Number(b.kev ?? false) - Number(a.kev ?? false) ||
    (b.epss ?? -1) - (a.epss ?? -1) ||
    (b.cvss ?? -1) - (a.cvss ?? -1)
  );
}

// ─── CVE Lookup ───

export async function cveLookup(cveId: string): Promise<CveDetails> {
  const id = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) throw new Error(`Invalid CVE ID "${cveId}" (expected format CVE-YYYY-NNNN).`);

  const data = await cvedbFetch(`/cve/${id}`);
  if (!data) throw new Error(`Shodan CVEDB has no information for ${id}.`);

  const cpes: string[] = data.cpes ?? [];
  return {
    ...normalizeSummary(data),
    cvssV2: data.cvss_v2 ?? undefined,
    cvssV3: data.cvss_v3 ?? undefined,
    cvssV4: data.cvss_v4 ?? undefined,
    proposeAction: data.propose_action ?? undefined,
    references: data.references ?? [],
    cpes: cpes.slice(0, 25),
    cpeCount: cpes.length,
    euvdId: data.euvd?.id ?? undefined,
  };
}

// ─── CVE Search ───

export async function cveSearch(opts: CveSearchOptions): Promise<CveSearchResult> {
  const params = new URLSearchParams();
  if (opts.cpe23) {
    const cpe = toCpe23(opts.cpe23);
    if (!cpe) throw new Error(`CPE "${opts.cpe23}" must include vendor, product and version (e.g. cpe:2.3:a:apache:http_server:2.4.7).`);
    params.set("cpe23", cpe);
  }
  if (opts.product) params.set("product", opts.product);
  if (opts.kevOnly) params.set("is_kev", "true");
  if (opts.sortByEpss) params.set("sort_by_epss", "true");
  if (opts.startDate) params.set("start_date", opts.startDate);
  if (opts.endDate) params.set("end_date", opts.endDate);
  params.set("limit", String(Math.max(1, Math.min(opts.limit ?? 50, 1000))));

  const data = await cvedbFetch(`/cves?${params}`);
  const cves: CveSummary[] = (data?.cves ?? []).map(normalizeSummary);

  return { query: Object.fromEntries(params), total: cves.length, cves };
}

// ─── Enrichment (used by osint_host_exposure) ───

/**
 * Resolve CVSS/EPSS/KEV for a set of CVE IDs. Queries CVEDB once per versioned CPE
 * first (cheap, covers most IDs), then looks up remaining IDs one by one up to `maxLookups`.
 */
export async function enrichCves(
  cveIds: string[],
  cpes: string[],
  maxLookups = 30,
): Promise<{ details: Map<string, CveSummary>; unresolved: string[]; errors: string[] }> {
  const wanted = new Set(cveIds.map((c) => c.toUpperCase()));
  const details = new Map<string, CveSummary>();
  const errors: string[] = [];

  const cpe23s = [...new Set(cpes.map(toCpe23).filter((c): c is string => !!c))];
  for (const cpe of cpe23s) {
    try {
      const res = await cveSearch({ cpe23: cpe, limit: 1000 });
      for (const c of res.cves) if (wanted.has(c.id)) details.set(c.id, c);
    } catch (err) {
      errors.push(`CVEDB ${cpe}: ${(err as Error).message}`);
    }
  }

  const remaining = [...wanted].filter((id) => !details.has(id));
  for (const id of remaining.slice(0, maxLookups)) {
    try {
      details.set(id, await cveLookup(id));
    } catch {
      /* unknown to CVEDB — leave unresolved */
    }
  }

  return { details, unresolved: [...wanted].filter((id) => !details.has(id)), errors };
}
