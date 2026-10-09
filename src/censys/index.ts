import { RateLimiter } from "../utils/rate-limiter.js";

const limiter = new RateLimiter(1000);

// Censys Platform API v3 (replaces the legacy Search API v2 at search.censys.io)
// Docs: https://docs.censys.com/reference/get-started
const CENSYS_BASE = "https://api.platform.censys.io/v3/global";

// ─── Types ───

export interface CensysAuth {
  /** Personal Access Token (PAT), sent as a Bearer token */
  token: string;
  /** Organization ID (UUID). Optional for Free users, required for Starter/Search/Core. */
  orgId?: string;
}

interface CensysVuln {
  id: string;
  severity?: string;
  cvss?: number;
  epss?: number;
  kev: boolean;
  cwes?: string[];
}

interface CensysRisk {
  id?: string;
  name?: string;
  severity?: string;
}

interface CensysService {
  port: number;
  serviceName: string;
  transportProtocol: string;
  certificate?: string;
  software?: string[];
  /** Software/components flagged end-of-life by Censys (Enterprise plans) */
  endOfLife?: string[];
  labels?: string[];
  /** CVEs (Censys Core/Enterprise plans) */
  vulns?: CensysVuln[];
  exposures?: CensysRisk[];
  misconfigs?: CensysRisk[];
  threats?: { name?: string; tactic?: string[]; type?: string[] }[];
  tls?: { versionSelected?: string; cipherSelected?: string; versions?: string[] };
  http?: { statusCode?: number; title?: string; path?: string }[];
  scanTime?: string;
}

interface CensysHost {
  ip: string;
  serviceCount?: number;
  services: CensysService[];
  location?: { country?: string; countryCode?: string; city?: string; province?: string };
  autonomousSystem?: { asn?: number; name?: string; bgpPrefix?: string; countryCode?: string };
  operatingSystem?: { vendor?: string; product?: string; version?: string };
  dnsNames?: string[];
  labels?: string[];
  vulnSummary?: { total: number; kev: number; critical: number; high: number };
}

interface CensysHostsResult {
  total: number;
  hosts: CensysHost[];
  query: string;
  nextPageToken?: string;
}

interface CensysCert {
  fingerprint: string;
  subject?: { commonName?: string; organization?: string };
  issuer?: { commonName?: string; organization?: string };
  subjectDn?: string;
  issuerDn?: string;
  validityStart?: string;
  validityEnd?: string;
  names: string[];
  revoked?: boolean;
}

interface CensysCertsResult {
  total: number;
  certificates: CensysCert[];
  query: string;
  nextPageToken?: string;
}

// ─── Helpers ───

async function censysFetch(method: string, path: string, auth: CensysAuth, body?: unknown): Promise<any> {
  await limiter.acquire();

  const url = new URL(`${CENSYS_BASE}${path}`);
  if (auth.orgId) url.searchParams.set("organization_id", auth.orgId);

  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${auth.token}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  if (!res.ok) {
    let detail = "";
    try {
      const err: any = await res.json();
      detail = err?.detail ?? err?.title ?? err?.message ?? JSON.stringify(err);
    } catch {
      /* ignore non-JSON error bodies */
    }
    let hint = "";
    if (res.status === 401) hint = " Check CENSYS_API_TOKEN (Personal Access Token from platform.censys.io).";
    else if (res.status === 403)
      hint = " Your plan may not include this endpoint, the token may lack the 'API Access' role, or CENSYS_ORG_ID is missing/wrong (required for Starter/Search/Core).";
    else if (res.status === 402 || res.status === 429) hint = " Out of credits or rate-limited.";
    throw new Error(`Censys API error: ${res.status} ${res.statusText}${detail ? ` — ${detail}` : ""}.${hint}`);
  }
  return res.json();
}

function first(arr: unknown): string | undefined {
  return Array.isArray(arr) && arr.length > 0 ? String(arr[0]) : undefined;
}

function nonEmpty<T>(arr: T[] | undefined): T[] | undefined {
  return arr && arr.length > 0 ? arr : undefined;
}

function list(x: unknown): any[] {
  return Array.isArray(x) ? x : [];
}

function softwareName(sw: any): string {
  return [sw.vendor, sw.product, sw.version].filter(Boolean).join(" ");
}

function normalizeVuln(v: any): CensysVuln {
  const m = v.metrics ?? {};
  return {
    id: v.id ?? v.name ?? "",
    severity: v.severity || undefined,
    cvss: m.cvss_v40?.score ?? m.cvss_v31?.score ?? m.cvss_v30?.score,
    epss: m.epss?.score,
    kev: list(v.kev).length > 0,
    cwes: nonEmpty(list(v.cwes).map((c) => c.entry).filter(Boolean)),
  };
}

/** Censys severity when present, otherwise derived from the CVSS score. */
function severityOf(v: CensysVuln): string | undefined {
  if (v.severity) return v.severity;
  if (v.cvss === undefined) return undefined;
  return v.cvss >= 9 ? "critical" : v.cvss >= 7 ? "high" : v.cvss >= 4 ? "medium" : "low";
}

function normalizeRisk(r: any): CensysRisk {
  return { id: r.id, name: r.name, severity: r.severity || undefined };
}

function normalizeService(s: any): CensysService {
  const software = list(s.software);
  const eol: string[] = [];
  for (const sw of software) {
    if (sw.life_cycle?.end_of_life) eol.push(softwareName(sw));
    for (const c of list(sw.components)) if (c.life_cycle?.end_of_life) eol.push(softwareName(c));
  }
  const httpEndpoints = list(s.endpoints)
    .filter((e) => e.http)
    .map((e) => ({ statusCode: e.http.status_code, title: e.http.html_title, path: e.path }));

  return {
    port: s.port,
    serviceName: s.protocol ?? "",
    transportProtocol: s.transport_protocol ?? "tcp",
    certificate: s.cert?.fingerprint_sha256,
    software: nonEmpty(software.map(softwareName).filter((x: string) => x.length > 0)),
    endOfLife: nonEmpty(eol),
    labels: nonEmpty(list(s.labels).map((l) => l.value ?? l).filter(Boolean)),
    vulns: nonEmpty(list(s.vulns).map(normalizeVuln)),
    exposures: nonEmpty(list(s.exposures).map(normalizeRisk)),
    misconfigs: nonEmpty(list(s.misconfigs).map(normalizeRisk)),
    threats: nonEmpty(list(s.threats).map((t) => ({ name: t.name, tactic: t.tactic ?? undefined, type: t.type ?? undefined }))),
    tls: s.tls
      ? {
          versionSelected: s.tls.version_selected || undefined,
          cipherSelected: s.tls.cipher_selected || undefined,
          versions: nonEmpty(list(s.tls.versions).map((v) => v.version).filter(Boolean)),
        }
      : undefined,
    http: nonEmpty(httpEndpoints),
    scanTime: s.scan_time,
  };
}

function normalizeHost(h: any, fallbackIp = ""): CensysHost {
  const os = h.operating_system;
  const services: CensysService[] = (h.services ?? []).map(normalizeService);
  const vulns = new Map<string, CensysVuln>();
  for (const svc of services) for (const v of svc.vulns ?? []) vulns.set(v.id, v);
  const all = [...vulns.values()];
  return {
    ip: h.ip ?? fallbackIp,
    serviceCount: h.service_count,
    services,
    location: h.location
      ? {
          country: h.location.country,
          countryCode: h.location.country_code,
          city: h.location.city,
          province: h.location.province,
        }
      : undefined,
    autonomousSystem: h.autonomous_system
      ? {
          asn: h.autonomous_system.asn,
          name: h.autonomous_system.name,
          bgpPrefix: h.autonomous_system.bgp_prefix,
          countryCode: h.autonomous_system.country_code,
        }
      : undefined,
    operatingSystem: os ? { vendor: os.vendor, product: os.product, version: os.version } : undefined,
    dnsNames: h.dns?.names,
    labels: Array.isArray(h.labels) ? h.labels.map((l: any) => l.value ?? l).filter(Boolean) : undefined,
    vulnSummary:
      all.length > 0
        ? {
            total: all.length,
            kev: all.filter((v) => v.kev).length,
            critical: all.filter((v) => severityOf(v) === "critical").length,
            high: all.filter((v) => severityOf(v) === "high").length,
          }
        : undefined,
  };
}

function normalizeCert(c: any): CensysCert {
  const p = c.parsed ?? {};
  return {
    fingerprint: c.fingerprint_sha256 ?? "",
    subject: p.subject
      ? { commonName: first(p.subject.common_name), organization: first(p.subject.organization) }
      : undefined,
    issuer: p.issuer
      ? { commonName: first(p.issuer.common_name), organization: first(p.issuer.organization) }
      : undefined,
    subjectDn: p.subject_dn,
    issuerDn: p.issuer_dn,
    validityStart: p.validity_period?.not_before,
    validityEnd: p.validity_period?.not_after,
    names: c.names ?? [],
    revoked: c.revoked,
  };
}

async function searchQuery(query: string, auth: CensysAuth, pageSize: number, pageToken?: string): Promise<any> {
  const data = await censysFetch("POST", "/search/query", auth, {
    query,
    page_size: Math.max(1, Math.min(pageSize, 100)),
    ...(pageToken ? { page_token: pageToken } : {}),
  });
  return data.result ?? {};
}

// ─── Host Search ───

/**
 * Search hosts with a CenQL query, e.g. `host.services.port=22 and host.location.country="Poland"`.
 */
export async function censysHosts(
  query: string,
  auth: CensysAuth,
  perPage = 25,
  pageToken?: string,
): Promise<CensysHostsResult> {
  const result = await searchQuery(query, auth, perPage, pageToken);
  const hosts: CensysHost[] = (result.hits ?? [])
    .filter((hit: any) => hit.host_v1)
    .map((hit: any) => normalizeHost(hit.host_v1.resource ?? {}));

  return {
    total: result.total_hits ?? hosts.length,
    hosts,
    query,
    nextPageToken: result.next_page_token || undefined,
  };
}

// ─── Host Details ───

export async function censysHostDetails(ip: string, auth: CensysAuth): Promise<CensysHost> {
  const data = await censysFetch("GET", `/asset/host/${encodeURIComponent(ip)}`, auth);
  return normalizeHost(data.result?.resource ?? {}, ip);
}

// ─── Certificate Search ───

/**
 * Search certificates with a CenQL query, e.g. `cert.names: "example.com"`.
 * A bare domain (no field prefix) is turned into a `cert.names` query.
 */
export async function censysCertificates(
  query: string,
  auth: CensysAuth,
  perPage = 25,
  pageToken?: string,
): Promise<CensysCertsResult> {
  const q = /^[a-z0-9*][a-z0-9.*-]*\.[a-z]{2,}$/i.test(query.trim()) ? `cert.names: "${query.trim()}"` : query;
  const result = await searchQuery(q, auth, perPage, pageToken);
  const certificates: CensysCert[] = (result.hits ?? [])
    .filter((hit: any) => hit.certificate_v1)
    .map((hit: any) => normalizeCert(hit.certificate_v1.resource ?? {}));

  return {
    total: result.total_hits ?? certificates.length,
    certificates,
    query: q,
    nextPageToken: result.next_page_token || undefined,
  };
}
