# mcphantom-detector

An offline Python CLI for detecting deprecated or archived MCP servers by name in client configuration files. Version 0.1.0; Python 3.9 or later; no runtime dependencies, network access, telemetry, or config writes.

McPhantom is the pattern in which AI coding agents install outdated MCP reference servers from stale training data. [Glow Labs reported it on 2026-11-10](https://www.glow.io/blogs/mcphantom-ai-coding-agents-are-installing-vulnerable-deprecated-mcp-servers-from-training-data). The bundled snapshot was coordinator-verified on **2026-11-11** against the npm registry's latest-version deprecation fields, GitHub's archive status, and the npm downloads API. The live `modelcontextprotocol/servers` repository remains maintained and is not flagged.

## Install

```sh
python3 -m pip install .
mcphantom-detector --version
python3 -m mcphantom_detector --version
```

## Usage

```sh
mcphantom-detector
mcphantom-detector scan ~/.cursor/mcp.json
python3 -m mcphantom_detector scan . --json --no-default-configs
mcphantom-detector . --fail-on medium --ignore /absolute/path/vendor/ --ignore /absolute/path/generated/
mcphantom-detector list
mcphantom-detector list --json
mcphantom-detector scan . --db my-snapshot.json --verbose
python3 -m unittest discover
```

`scan` is the default subcommand. With no paths, discovery walks the current directory and adds existing home configs: `~/.claude.json`, `~/.config/Claude/claude_desktop_config.json`, `~/Library/Application Support/Claude/claude_desktop_config.json`, `~/.cursor/mcp.json`, `~/.codex/config.toml`, and `~/.vscode/mcp.json`. `--no-default-configs` suppresses the home locations while retaining the current-directory scan. Explicit paths scan only those paths.

Directory walks parse only `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.claude.json`, `claude.json`, and `config.toml`; symlinks are not followed. Explicit files are read regardless of basename. JSON uses `mcpServers`; TOML uses `mcp_servers`. On Python 3.9/3.10 a minimal line parser supports command, args and url strings and strips comments outside strings.

Scoped package tokens match case-insensitively in recursive JSON string values. Unscoped names match command tokens or args elements, never free-form description text. Version suffixes match; fork suffixes do not. Archived-repo references with a named source identify that server; otherwise they produce one generic MEDIUM finding. Duplicate package references within one server entry yield one finding.

The single rule is `deprecated-mcp-server`. Puppeteer is HIGH; other database entries and generic archive references are MEDIUM. Exit codes: **0** when no finding reaches the threshold; **2** for a HIGH finding by default, or any finding with `--fail-on medium`; **1** for usage, root I/O, database, or explicitly supplied malformed-config errors. Malformed configs discovered by walking generate stderr warnings without changing the exit status. `--verbose` lists attempted files on stderr.

Scan JSON is an object with a `findings` array, sorted by file, server, package. Each finding has exactly `rule`, `severity`, `package`, `server`, `file`, and `message`. Human output has one line per finding and a summary. Each repeatable `--ignore PREFIX` takes a single value and skips findings whose absolute file path starts with that prefix.

`--db PATH` replaces the bundled snapshot with a JSON list of objects using the fields `package`, `short`, `status`, `deprecation`, `downloads`, `known_vulnerability`, and `repo`. Text and download values may be null where appropriate. `list --json` shows the complete schema. The loader rejects malformed databases.

## Bundled database

The 12 npm entries below have latest-version deprecation messages. Downloads are npm-API totals for **2025-07-10..2026-11-11**, summing to **19,082,003**.

| Package | Status | Downloads |
| --- | --- | ---: |
| `@modelcontextprotocol/server-github` | deprecated | 5,743,844 |
| `@modelcontextprotocol/server-postgres` | deprecated | 4,760,500 |
| `@modelcontextprotocol/server-slack` | deprecated | 3,757,141 |
| `@modelcontextprotocol/server-puppeteer` | deprecated | 1,582,178 |
| `@modelcontextprotocol/server-brave-search` | deprecated | 1,545,289 |
| `@modelcontextprotocol/server-google-maps` | deprecated | 834,859 |
| `@modelcontextprotocol/server-gitlab` | deprecated | 290,473 |
| `@modelcontextprotocol/server-gdrive` | deprecated | 266,018 |
| `@modelcontextprotocol/server-redis` | deprecated | 141,723 |
| `@modelcontextprotocol/create-server` | deprecated | 123,166 |
| `@modelcontextprotocol/server-aws-kb-retrieval` | deprecated | 23,626 |
| `@modelcontextprotocol/server-everart` | deprecated | 13,186 |
| `@modelcontextprotocol/server-git` | archived-source-only | — |
| `@modelcontextprotocol/server-sentry` | archived-source-only | — |
| `@modelcontextprotocol/server-sqlite` | archived-source-only | — |
| `@modelcontextprotocol/server-fetch` | maintained-source-only | — |
| `@modelcontextprotocol/server-time` | maintained-source-only | — |

The five source-only entries (three archived, two maintained) have no published npm package under these scoped names; deprecation and downloads are null. The bundled JSON ships in both distributions and is read locally at runtime.

## Differentiation

**Compared with mcp-audit:** mcp-audit checks installed server versions against known CVEs and can write fixes. mcphantom-detector flags deprecated or archived servers by name before installation. It has no CVE table, version checks, or fix-writing logic; these are separate detection families with no rule overlap.

**Compared with Glow Glowy:** Glowy is an enterprise fleet product. This is a local offline CLI for inspecting config files.

## Honest limitations

The database is a snapshot dated **2026-11-11**. Servers deprecated after that date are not covered unless you supply an updated `--db`. Only config files are scanned; servers installed outside any config are invisible. This is static name matching, not runtime verification.

The download figures use the npm API window **2025-07-10..2026-11-11**. The article reported **17.35M** (17,352,267) at publication; its window and counting method differ from this explicitly dated 19,082,003 total.

Glow reported four high-severity vulnerabilities, but only the puppeteer remote code execution issue is publicly named. Its maintainers declined a fix; no CVE was assigned. The other 11 npm entries are flagged on deprecation status alone, not on a named CVE.

The tool flags configs; it cannot block `npx` from installing a deprecated package. `npx` can install it with only a warning.

MIT licensed. Tests use the standard library and a fixed database oracle.
