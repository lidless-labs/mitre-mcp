# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Docs
- Rewrote the README to lead with what mitre-mcp is, why it exists, and how it
  differs, with a copy-paste `npx -y mitre-mcp` MCP client config and the full
  39-tool / 3-resource / 4-prompt reference verified against the server source.
- Added a "Why not something else?" comparison and a "What mitre-mcp is not"
  boundaries section.
- Switched example SOC hosts to the RFC 5737 documentation address
  (`192.0.2.10`).

### Added
- Maintainer-health files: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates (`bug`, `feature`, plus a config
  that disables blank issues and routes questions off-issue), and a pull
  request template with a no-PII / content-guard checklist.

## [2.0.1] - 2026-06-10

Security hardening release. Everything below was already on `main` but had not
shipped to npm; this release delivers it.

### Security
- Scoped TLS verification disable per request: when `*_VERIFY_SSL=false`, the
  relaxed TLS setting now applies only to that integration's requests via a
  dedicated undici dispatcher, instead of disabling certificate validation
  process-wide.
- User-supplied IDs are now validated against strict allow-list patterns and
  URL-encoded before being interpolated into SOC API paths (Wazuh, TheHive,
  Cortex, MISP).
- The three state-changing SOC tools (`mitre_misp_create_event`,
  `mitre_thehive_create_case`, `mitre_cortex_run_analyzers`) are now gated:
  they dry-run by default and execute only with per-call `confirm: true` or
  the `MITRE_SOC_ALLOW_WRITES` environment variable.
- SOC API responses are parsed defensively by content type.

### Changed
- The MCP server version is derived from `package.json` instead of a
  hardcoded constant, so the version reported to clients can no longer drift.
- CI now runs `./scripts/verify` (typecheck, tests, build), and test failures
  fail the build. Previously CI skipped typecheck and ignored test failures.
- The npm publish job skips re-publishing when the version already exists.
- Refreshed npm dependencies.

### Fixed
- Stripped a stray MCP schema marker from tool registration.

### Added
- `AGENTS.md` repository guidance and the `scripts/verify` single
  verification entrypoint.
- Content-guard pre-push hook to keep secrets and internal hosts out of
  the public repo.
- Security regression tests (`tests/soc-security.test.ts`).
- This changelog.

### Docs
- Refreshed README banner and badges; sanitized SOC integration host
  examples to `*.example.internal` placeholders.

## [2.0.0] - 2026-04-30

Major feature release expanding from 19 to 39 tools.

### Added
- Wazuh integration (4 tools): manager status, alert-to-ATT&CK mapping,
  MITRE rule coverage analysis, and ATT&CK-enriched alert retrieval.
- TheHive integration (3 tools): case enrichment with techniques and
  mitigations, case creation with ATT&CK context and tasks, and case
  listing filtered by technique.
- Cortex integration (2 tools): analyzer-to-data-source coverage mapping
  and analyzer execution with ATT&CK context.
- MISP integration (4 tools): event-to-ATT&CK mapping via galaxies and
  tags, IOC search by technique or group, event creation pre-tagged with
  ATT&CK, and event listing with enrichment.
- Cross-stack tools (2): SOC connection status and cross-platform
  technique correlation across Wazuh, TheHive, and MISP.
- Campaign support: STIX campaign parsing plus get, list, search, and
  profile tools.
- ATT&CK Navigator layer JSON export (coverage, group, campaign, and diff
  modes).
- GitHub Actions CI with automatic npm publish on version tags.
- Proxmox LXC installer script and MIT license.

### Changed
- All SOC integrations are optional and configured via environment
  variables.

## [1.0.0] - 2026-03-21

### Added
- Initial release: MCP server (stdio) for the MITRE ATT&CK knowledge base
  with 19 core tools covering techniques, tactics, groups, software,
  mitigations, data sources, detection coverage, alert mapping, and data
  management, plus MCP resources and prompts.
- STIX 2.1 bundle download, parsing, and local caching for Enterprise,
  Mobile, and ICS ATT&CK.
