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

interface CensysService {
  port: number;
  serviceName: string;
  transportProtocol: string;
  certificate?: string;
  software?: string[];
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

function normalizeService(s: any): CensysService {
  return {
    port: s.port,
    serviceName: s.protocol ?? "",
    transportProtocol: s.transport_protocol ?? "tcp",
    certificate: s.cert?.fingerprint_sha256,
    software: Array.isArray(s.software)
      ? s.software
          .map((sw: any) => [sw.vendor, sw.product, sw.version].filter(Boolean).join(" "))
          .filter((x: string) => x.length > 0)
      : undefined,
    scanTime: s.scan_time,
  };
}

function normalizeHost(h: any, fallbackIp = ""): CensysHost {
  const os = h.operating_system;
  return {
    ip: h.ip ?? fallbackIp,
    serviceCount: h.service_count,
    services: (h.services ?? []).map(normalizeService),
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
