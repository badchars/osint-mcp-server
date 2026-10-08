# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`osint-mcp-server` — part of an MCP security suite (alongside cve-mcp, github-security-mcp, cloud-audit-mcp, hackbrowser-mcp, which share this architecture). Exposes 37 OSINT tools to AI agents over MCP stdio, and the same tools as a one-shot CLI and a GitHub Action. Published on npm as `npx osint-mcp-server`.

Free sources (no key): DNS, WHOIS/RDAP, crt.sh, GeoIP (ip-api.com), BGP (bgpview.io), Wayback CDX, HackerTarget, Microsoft 365 tenant discovery. Paid sources (optional env keys): Shodan, VirusTotal, SecurityTrails, Censys.

## Commands

```bash
bun install
bun run dev                     # watch mode: bun --watch run src/index.ts
bun run build                   # tsc -p tsconfig.build.json → dist/
node dist/index.js --list       # list all tools by category
node dist/index.js --tool dns_lookup '{"domain":"example.com","type":"A"}'          # run one tool
node dist/index.js --tool osint_domain_recon '{"domain":"example.com"}' --format text
bun run src/index.ts --tool <name> '<json>'   # same, without building
```

There is no linter and no test suite. CI (`.github/workflows/ci.yml`) only builds and smoke-tests `--list`, `--help`, and a `dns_lookup` call — run the same after changes. If tests are added, use `bun test`.

## Architecture

Three entry modes, one tool registry:

- `src/index.ts` — parses argv. `--help` / `--list` / `--tool <name> [json] [--format json|text]` run tools directly via `tool.execute()` (CLI + GitHub Action path); no flags → `startMcpStdio()`. `buildToolContext()` reads env vars into `ctx.config`.
- `src/protocol/mcp-server.ts` — loops `allTools`, registers each with `server.tool(name, description, schema, handler)`, and wraps execution in try/catch so thrown errors become `isError` text results instead of crashing the server.
- `src/protocol/tools.ts` — every `ToolDef` lives here (grouped by provider with banner comments) and is collected into `export const allTools`. Tool defs are thin: Zod schema with `.describe()` per param, then `json(await providerFn(...))`.
- `src/<provider>/index.ts` — pure async functions using native `fetch` (or `dns/promises`). Each module creates its own module-level `RateLimiter` and `TTLCache` instances and normalizes API responses into local interfaces.
- `src/meta/` — `sources.ts` (`osint_list_sources`: static table of sources with key status) and `recon.ts` (`osint_domain_recon`: fans out to free providers with `Promise.allSettled`, collecting failures into `errors[]` rather than failing).
- `src/types/index.ts` — `ToolDef`, `ToolContext`, `ToolResult`, plus `text()` / `json()` helpers.

### API keys

`ctx.config` uses camelCase keys: `shodanApiKey`, `vtApiKey`, `stApiKey`, `censysApiToken`, `censysOrgId` (from `SHODAN_API_KEY`, `VT_API_KEY`, `ST_API_KEY`, `CENSYS_API_TOKEN`, `CENSYS_ORG_ID`). Paid tools call `requireApiKey(key, provider, envVar)` from `src/utils/require-key.ts`, which throws a descriptive "set X env var" error that the MCP wrapper / CLI surfaces as text. Censys uses the Platform API (personal access token; org ID needed for paid plans).

## Adding or Removing a Tool

Tool counts and names are duplicated in several places that must be kept in sync by hand:

1. Provider function in `src/<provider>/index.ts`
2. `ToolDef` + entry in `allTools` in `src/protocol/tools.ts`
3. `TOOL_CATEGORIES` and the counts in `printHelp()` in `src/index.ts` (tools missing from `TOOL_CATEGORIES` won't appear in `--list`)
4. `toolCount` in `src/meta/sources.ts` (and a new entry there for a new provider; new env vars also go in `buildToolContext()` and `ToolContext`)
5. Tool count in `action.yml`, `package.json` description/keywords, `README.md` and all 21 translated `README.*.md` files, `CHANGELOG.md`

Naming: provider prefix + action in snake_case (`shodan_host`, `vt_subdomains`, `st_dns_history`, `hackertarget_reverseip`, `m365_tenant`).

Note: `CONTRIBUTING.md`'s project structure and "Adding a New Tool" example (`src/tools/<provider>/`, `inputSchema`, `z.object`) are outdated — follow the actual pattern in `src/protocol/tools.ts` (`schema` is a plain `Record<string, ZodType>`).

## Rules

- Runtime is Bun for dev, but published output must run on Node (≥20, used by the GitHub Action). Two tsconfigs: `tsconfig.json` (Bun types) and `tsconfig.build.json` (Node types, emits `dist/`). Use `.js` extensions in relative imports (ESM).
- Dependencies are limited to `@modelcontextprotocol/sdk` and `zod` — use native `fetch` and `dns/promises`, no HTTP clients.
- All API keys stay optional; missing keys must produce a descriptive message naming the env var.
- Every tool parameter needs a Zod schema with `.describe()`.
- npm package ships only `dist/` and `action.yml`; `prepublishOnly` runs the build.
