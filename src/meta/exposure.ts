import type { ToolContext } from "../types/index.js";
import { internetdbHost } from "../internetdb/index.js";
import { enrichCves, comparePriority, type CveSummary } from "../cvedb/index.js";
import { shodanHost } from "../shodan/index.js";
import { censysHostDetails } from "../censys/index.js";

// ─── Types ───

interface ExposedCve {
  cve: string;
  cvss?: number;
  epss?: number;
  kev: boolean;
  verified?: boolean;
  summary?: string;
}

interface Weakness {
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  detail: string;
}

interface HostExposureResult {
  ip: string;
  sources: string[];
  ports: number[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
  cves: ExposedCve[];
  cveSummary: { total: number; kev: number; critical: number; high: number; verified: number };
  weaknesses: Weakness[];
  unresolvedCves: string[];
  errors: string[];
}

// Services that are risky when exposed directly to the internet.
const RISKY_PORTS: Record<number, string> = {
  21: "FTP", 23: "Telnet (cleartext)", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
  1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
  5900: "VNC", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached",
  27017: "MongoDB", 2375: "Docker API", 2379: "etcd", 9000: "exposed admin/API",
};

const TAG_WEAKNESS: Record<string, { severity: Weakness["severity"]; detail: string }> = {
  "self-signed": { severity: "low", detail: "Self-signed TLS certificate" },
  "eol-product": { severity: "high", detail: "End-of-life product (no security updates)" },
  "eol-os": { severity: "high", detail: "End-of-life operating system (no security updates)" },
  "expired": { severity: "medium", detail: "Expired TLS certificate" },
  "compromised": { severity: "critical", detail: "Host flagged as compromised" },
  "malware": { severity: "critical", detail: "Malware associated with host" },
  "c2": { severity: "critical", detail: "Command-and-control infrastructure" },
  "open-dir": { severity: "medium", detail: "Open directory listing" },
  "ssh-bad-key": { severity: "high", detail: "SSH host using a known/compromised key" },
  "doublepulsar": { severity: "critical", detail: "DoublePulsar backdoor implant" },
  "honeypot": { severity: "info", detail: "Likely a honeypot" },
};

const WEAK_TLS = new Set(["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "tlsv1_0", "tlsv1_1", "ss_lv_2", "ss_lv_3"]);
const SEVERITY_RANK: Weakness["severity"][] = ["critical", "high", "medium", "low", "info"];

// ─── Host Exposure ───

/**
 * Passive vulnerability/weakness overview for a single IP. Always queries the free
 * Shodan InternetDB, enriches CVEs through CVEDB, and folds in Shodan + Censys host
 * details when their API keys are configured. Never fails as a whole — per-source
 * failures are collected in `errors`.
 */
export async function hostExposure(ip: string, ctx: ToolContext): Promise<HostExposureResult> {
  const errors: string[] = [];
  const sources: string[] = [];
  const ports = new Set<number>();
  const hostnames = new Set<string>();
  const cpes = new Set<string>();
  const tags = new Set<string>();
  const cveIds = new Set<string>();
  const weaknesses: Weakness[] = [];
  // Best known detail per CVE, merged across sources.
  const cveMeta = new Map<string, Partial<ExposedCve>>();

  const mergeCve = (id: string, meta: Partial<ExposedCve> = {}) => {
    const up = id.toUpperCase();
    cveIds.add(up);
    const cur = cveMeta.get(up) ?? {};
    cveMeta.set(up, {
      cvss: meta.cvss ?? cur.cvss,
      epss: meta.epss ?? cur.epss,
      kev: meta.kev ?? cur.kev,
      verified: cur.verified || meta.verified,
      summary: cur.summary ?? meta.summary,
    });
  };

  const [idb, shodanRes, censysRes] = await Promise.allSettled([
    internetdbHost(ip),
    ctx.config.shodanApiKey ? shodanHost(ip, ctx.config.shodanApiKey) : Promise.resolve(null),
    ctx.config.censysApiToken
      ? censysHostDetails(ip, { token: ctx.config.censysApiToken, orgId: ctx.config.censysOrgId || undefined })
      : Promise.resolve(null),
  ]);

  // InternetDB (free)
  if (idb.status === "fulfilled") {
    sources.push("InternetDB");
    const d = idb.value;
    for (const p of d.ports) ports.add(p);
    for (const h of d.hostnames) hostnames.add(h);
    for (const c of d.cpes) cpes.add(c);
    for (const t of d.tags) tags.add(t);
    for (const v of d.vulns) mergeCve(v);
  } else {
    errors.push(`InternetDB: ${idb.reason}`);
  }

  // Shodan host (optional, richest — carries verified/CVSS/KEV)
  if (shodanRes.status === "fulfilled" && shodanRes.value) {
    sources.push("Shodan");
    const d = shodanRes.value;
    for (const p of d.ports) ports.add(p);
    for (const h of d.hostnames) hostnames.add(h);
    for (const t of d.tags ?? []) tags.add(t);
    for (const v of d.vulnDetails) mergeCve(v.cve, { cvss: v.cvss, epss: v.epss, kev: v.kev, verified: v.verified, summary: v.summary });
    for (const svc of d.services) {
      for (const c of svc.cpe ?? []) cpes.add(c);
      for (const t of svc.tags ?? []) tags.add(t);
      if (svc.ssl?.certExpired) weaknesses.push({ severity: "medium", category: "tls", detail: `Expired TLS certificate on port ${svc.port}` });
      for (const ver of svc.ssl?.versions ?? []) {
        if (WEAK_TLS.has(ver)) weaknesses.push({ severity: "medium", category: "tls", detail: `Deprecated ${ver} enabled on port ${svc.port}` });
      }
    }
  } else if (shodanRes.status === "rejected") {
    errors.push(`Shodan: ${shodanRes.reason}`);
  }

  // Censys host (optional)
  if (censysRes.status === "fulfilled" && censysRes.value) {
    sources.push("Censys");
    const d = censysRes.value;
    for (const h of d.dnsNames ?? []) hostnames.add(h);
    for (const l of d.labels ?? []) tags.add(l.toLowerCase());
    for (const svc of d.services) {
      ports.add(svc.port);
      for (const v of svc.vulns ?? []) mergeCve(v.id, { cvss: v.cvss, epss: v.epss, kev: v.kev });
      for (const e of svc.endOfLife ?? []) weaknesses.push({ severity: "high", category: "eol", detail: `End-of-life software on port ${svc.port}: ${e}` });
      for (const t of svc.threats ?? []) weaknesses.push({ severity: "critical", category: "threat", detail: `${t.name ?? "Threat"} on port ${svc.port}${t.tactic?.length ? ` (${t.tactic.join(", ")})` : ""}` });
      for (const m of svc.misconfigs ?? []) weaknesses.push({ severity: "medium", category: "misconfig", detail: `${m.name ?? m.id ?? "Misconfiguration"} on port ${svc.port}` });
      for (const ver of svc.tls?.versions ?? []) {
        if (WEAK_TLS.has(ver)) weaknesses.push({ severity: "medium", category: "tls", detail: `Deprecated ${ver} on port ${svc.port}` });
      }
    }
  } else if (censysRes.status === "rejected") {
    errors.push(`Censys: ${censysRes.reason}`);
  }

  // Enrich CVEs that lack CVSS/EPSS/KEV via the free CVEDB.
  const needEnrich = [...cveIds].filter((id) => cveMeta.get(id)?.cvss === undefined || cveMeta.get(id)?.kev === undefined);
  let unresolved: string[] = [];
  if (needEnrich.length > 0) {
    const { details, unresolved: un, errors: cvErrs } = await enrichCves(needEnrich, [...cpes]);
    unresolved = un;
    errors.push(...cvErrs);
    for (const [id, info] of details) mergeCve(id, info as CveSummary);
  }

  // Risky exposed ports → weaknesses
  for (const port of ports) {
    if (RISKY_PORTS[port]) weaknesses.push({ severity: "high", category: "exposed-service", detail: `${RISKY_PORTS[port]} exposed on port ${port}` });
  }
  // Tag-based weaknesses
  for (const t of tags) {
    const w = TAG_WEAKNESS[t];
    if (w) weaknesses.push({ severity: w.severity, category: "tag", detail: w.detail });
  }

  const cves: ExposedCve[] = [...cveMeta.entries()]
    .map(([cve, m]) => ({ cve, cvss: m.cvss, epss: m.epss, kev: m.kev ?? false, verified: m.verified, summary: m.summary }))
    .sort(comparePriority);

  // Deduplicate weaknesses and sort by severity.
  const seen = new Set<string>();
  const uniqueWeaknesses = weaknesses
    .filter((w) => (seen.has(w.detail) ? false : seen.add(w.detail)))
    .sort((a, b) => SEVERITY_RANK.indexOf(a.severity) - SEVERITY_RANK.indexOf(b.severity));

  return {
    ip,
    sources,
    ports: [...ports].sort((a, b) => a - b),
    hostnames: [...hostnames].sort(),
    cpes: [...cpes].sort(),
    tags: [...tags].sort(),
    cves,
    cveSummary: {
      total: cves.length,
      kev: cves.filter((c) => c.kev).length,
      critical: cves.filter((c) => (c.cvss ?? 0) >= 9).length,
      high: cves.filter((c) => (c.cvss ?? 0) >= 7 && (c.cvss ?? 0) < 9).length,
      verified: cves.filter((c) => c.verified).length,
    },
    weaknesses: uniqueWeaknesses,
    unresolvedCves: unresolved,
    errors,
  };
}
