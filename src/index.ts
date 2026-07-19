#!/usr/bin/env node
import { startMcpStdio } from "./protocol/mcp-server.js";
import { allTools } from "./protocol/tools.js";
import type { ToolContext, ToolDef } from "./types/index.js";

// ─── Tool Context ───

function buildToolContext(): ToolContext {
  return {
    config: {
      shodanApiKey: process.env.SHODAN_API_KEY,
      vtApiKey: process.env.VT_API_KEY,
      stApiKey: process.env.ST_API_KEY,
      censysApiId: process.env.CENSYS_API_ID,
      censysApiSecret: process.env.CENSYS_API_SECRET,
      xquikApiKey: process.env.XQUIK_API_KEY,
    },
  };
}

// ─── Tool Categories (for --list display) ───

const TOOL_CATEGORIES: { label: string; env: string | null; tools: string[] }[] = [
  {
    label: "DNS",
    env: null,
    tools: ["dns_lookup", "dns_reverse", "dns_email_security", "dns_spf_chain", "dns_srv_discover", "dns_wildcard_check"],
  },
  { label: "WHOIS / RDAP", env: null, tools: ["whois_domain", "whois_ip"] },
  { label: "Certificate Transparency", env: null, tools: ["crtsh_search"] },
  { label: "GeoIP", env: null, tools: ["geoip_lookup", "geoip_batch"] },
  { label: "BGP / ASN", env: null, tools: ["bgp_asn", "bgp_ip", "bgp_prefix"] },
  { label: "Wayback Machine", env: null, tools: ["wayback_urls", "wayback_snapshots"] },
  { label: "HackerTarget", env: null, tools: ["hackertarget_hostsearch", "hackertarget_reverseip", "hackertarget_aslookup"] },
  { label: "Microsoft 365", env: null, tools: ["m365_tenant", "m365_userrealm"] },
  { label: "Meta", env: null, tools: ["osint_list_sources", "osint_domain_recon"] },
  { label: "Shodan", env: "SHODAN_API_KEY", tools: ["shodan_host", "shodan_search", "shodan_dns_resolve", "shodan_exploits"] },
  { label: "VirusTotal", env: "VT_API_KEY", tools: ["vt_domain", "vt_ip", "vt_subdomains", "vt_url"] },
  { label: "SecurityTrails", env: "ST_API_KEY", tools: ["st_subdomains", "st_dns_history", "st_whois"] },
  { label: "Censys", env: "CENSYS_API_ID + CENSYS_API_SECRET", tools: ["censys_hosts", "censys_host_details", "censys_certificates"] },
  { label: "Xquik", env: "XQUIK_API_KEY", tools: ["xquik_tweet", "xquik_search_tweets", "xquik_user"] },
];

// ─── CLI: Print Help ───

function printHelp(): void {
  console.log("osint-mcp-server — OSINT intelligence for AI agents & CI/CD pipelines");
  console.log("");
  console.log("Usage:");
  console.log("  osint-mcp-server                                        Start MCP server (stdio)");
  console.log("  osint-mcp-server --tool <name> [json-args] [--format]   Run a single tool");
  console.log("  osint-mcp-server --list                                 List all available tools");
  console.log("");
  console.log("Examples:");
  console.log('  osint-mcp-server --tool dns_lookup \'{"domain":"example.com","type":"A"}\'');
  console.log('  osint-mcp-server --tool osint_domain_recon \'{"domain":"example.com"}\'');
  console.log('  osint-mcp-server --tool dns_email_security \'{"domain":"example.com"}\' --format text');
  console.log('  osint-mcp-server --tool shodan_host \'{"ip":"1.1.1.1"}\'');
  console.log("");
  console.log("Options:");
  console.log("  --tool <name>     Run a specific tool by name");
  console.log("  --list            List all 40 tools with descriptions");
  console.log("  --format <type>   Output format: json (default) or text");
  console.log("  --help, -h        Show this help message");
  console.log("");
  console.log("Environment variables (all optional):");
  console.log("  SHODAN_API_KEY       Enables 4 Shodan tools");
  console.log("  VT_API_KEY           Enables 4 VirusTotal tools");
  console.log("  ST_API_KEY           Enables 3 SecurityTrails tools");
  console.log("  CENSYS_API_ID        Enables 3 Censys tools");
  console.log("  CENSYS_API_SECRET    Required with CENSYS_API_ID");
  console.log("  XQUIK_API_KEY        Enables 3 Xquik tools");
  console.log("");
  console.log("Without any flags, starts an MCP server on stdio (for AI agents).");
  console.log("21 tools work without API keys (DNS, WHOIS, crt.sh, BGP, GeoIP, Wayback, HackerTarget, M365).");
}

// ─── CLI: Print Tool List ───

function printToolList(): void {
  const toolMap = new Map<string, ToolDef>();
  for (const t of allTools) toolMap.set(t.name, t);

  console.log(`Available tools (${allTools.length}):\n`);

  for (const cat of TOOL_CATEGORIES) {
    const authLabel = cat.env ? cat.env : "No API key";
    console.log(`  ${cat.label} (${authLabel}):`);
    for (const name of cat.tools) {
      const tool = toolMap.get(name);
      if (tool) {
        const desc = tool.description.length > 70
          ? tool.description.slice(0, 67) + "..."
          : tool.description;
        console.log(`    ${name.padEnd(28)} ${desc}`);
      }
    }
    console.log("");
  }
}

// ─── CLI: Format as Text ───

function formatAsText(data: unknown, indent = 0): string {
  const pad = "  ".repeat(indent);
  if (data === null || data === undefined) return `${pad}null`;
  if (typeof data !== "object") return `${pad}${data}`;
  if (Array.isArray(data)) {
    if (data.length === 0) return `${pad}(empty)`;
    return data.map((item, i) => {
      if (typeof item === "object" && item !== null) {
        return `${pad}[${i}]\n${formatAsText(item, indent + 1)}`;
      }
      return `${pad}- ${item}`;
    }).join("\n");
  }
  const entries = Object.entries(data as Record<string, unknown>);
  return entries.map(([key, val]) => {
    if (typeof val === "object" && val !== null) {
      return `${pad}${key}:\n${formatAsText(val, indent + 1)}`;
    }
    return `${pad}${key}: ${val}`;
  }).join("\n");
}

// ─── CLI: Run Tool ───

async function runCliTool(toolName: string, jsonArgs: string, format: string): Promise<void> {
  const ctx = buildToolContext();
  const tool = allTools.find((t) => t.name === toolName);

  if (!tool) {
    console.error(`Error: Unknown tool "${toolName}"`);
    console.error(`Run "osint-mcp-server --list" to see available tools.`);
    process.exit(1);
  }

  let parsedArgs: Record<string, unknown>;
  try {
    parsedArgs = JSON.parse(jsonArgs);
  } catch {
    console.error(`Error: Invalid JSON arguments: ${jsonArgs}`);
    process.exit(1);
  }

  try {
    const result = await tool.execute(parsedArgs, ctx);
    const output = result.content[0]?.text ?? "";

    if (format === "text") {
      try {
        const data = JSON.parse(output);
        console.log(formatAsText(data));
      } catch {
        console.log(output);
      }
    } else {
      console.log(output);
    }
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
}

// ─── Main ───

async function main() {
  const args = process.argv.slice(2);

  // Help
  if (args.includes("--help") || args.includes("-h")) {
    printHelp();
    process.exit(0);
  }

  // List tools
  if (args.includes("--list")) {
    printToolList();
    process.exit(0);
  }

  // CLI mode: --tool <name> [json-args] [--format json|text]
  const toolIdx = args.indexOf("--tool");
  if (toolIdx !== -1) {
    const toolName = args[toolIdx + 1];
    if (!toolName || toolName.startsWith("--")) {
      console.error("Error: --tool requires a tool name.");
      console.error('Example: osint-mcp-server --tool dns_lookup \'{"domain":"example.com","type":"A"}\'');
      process.exit(1);
    }

    // Find JSON args (next non-flag argument after tool name)
    let jsonArgs = "{}";
    const nextArg = args[toolIdx + 2];
    if (nextArg && !nextArg.startsWith("--")) {
      jsonArgs = nextArg;
    }

    const formatIdx = args.indexOf("--format");
    const format = formatIdx !== -1 && args[formatIdx + 1] ? args[formatIdx + 1] : "json";

    await runCliTool(toolName, jsonArgs, format);
    process.exit(0);
  }

  // Default: MCP stdio mode
  const ctx = buildToolContext();
  await startMcpStdio(ctx);
  await new Promise(() => {});
}

main().catch((err) => {
  console.error("[osint-mcp-server] Fatal:", err);
  process.exit(1);
});
