# Contributing to mitre-mcp

mitre-mcp is an MCP server for the MITRE ATT&CK knowledge base, with optional integrations for a live SOC stack (Wazuh, TheHive, Cortex, MISP). Patches are welcome. Before you start, please skim this file so we both spend our time on the right things.

## What kinds of changes land easily

- **Bug fixes** in the ATT&CK query layer, the STIX loader/parser, a tool handler, or a SOC client.
- **New ATT&CK tools** that surface data already in the STIX bundles (a sharper search, a new relationship walk, a better Navigator layer mode).
- **SOC client robustness**: better error handling, more defensive response parsing, clearer dry-run output.
- **Test coverage** for any of the above, especially the SOC security regressions.
- **Docs**: clearer setup, more client examples, better tool descriptions.

## What needs a conversation first

- **A new SOC integration** (a fifth platform). Open an issue first describing the platform, its API shape, and the tools you would add. New integrations are a real maintenance surface.
- **Breaking changes** to tool names, tool input schemas, resource URIs, or prompt names. These are the public MCP surface and renaming them breaks every client config in the wild.
- **Anything that loosens the SOC write gate or the SOC ID validation.** These exist on purpose; see [SECURITY.md](SECURITY.md).
- **A new runtime dependency.** The server is deliberately lean (`@modelcontextprotocol/sdk`, `undici`, `zod`). Adding to that list needs a reason.

## What does not land

- Personal details, real hostnames, real private IPs, account IDs, tokens, or live auth profiles in code, tests, or docs. Example hosts use the [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) range (`192.0.2.x`). The content-guard pre-push hook and CI will fail if they find anything else.
- A state-changing SOC tool that writes without going through the `confirm` / `MITRE_SOC_ALLOW_WRITES` gate.
- AI co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Local dev

```bash
git clone https://github.com/lidless-labs/mitre-mcp.git
cd mitre-mcp
npm install
npm run build
```

Run the full verification the same way CI does:

```bash
./scripts/verify       # typecheck, tests, build
```

Or the individual steps:

```bash
npm run typecheck      # tsc --noEmit
npm test               # vitest run
npm run build          # tsup
npm run dev            # tsx watch src/index.ts (live reload while developing)
```

## Adding an ATT&CK tool

Core tools live under `src/tools/` and are registered by a `register*Tools(server, ...)` function imported in `src/index.ts`. To add one:

1. Add the handler to the relevant file under `src/tools/` (or a new file).
2. Register it inside that file's `register*Tools` function with a `mitre_`-prefixed name, a Zod input schema, and a clear description.
3. If you added a new file, import and call its register function from `src/index.ts`.
4. Add a test under `tests/` and a row to the tool table in `README.md`.

SOC tools follow the same pattern under `src/soc/`. Any state-changing SOC tool must route through the shared write-gate helper in `src/soc/util.ts`.

## Filing issues

Please use the templates under [.github/ISSUE_TEMPLATE/](.github/ISSUE_TEMPLATE). Before posting any output, remove tokens, private hostnames, private IPs, and unredacted absolute paths.

## License

By contributing you agree that your contribution is licensed under the MIT License, the same as the rest of the repo.
