# Security Policy

## Supported versions

Only the latest release on npm and the `main` branch receive security fixes. Pin to a released tag if you need a known-good version.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Email **me@solomonneas.dev** with: <!-- content-guard: allow pii/email -->

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The version or commit you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow up; the mail may have been filtered.

## In scope

- Command injection, path traversal, or SSRF flaws in mitre-mcp's own code (the MCP server, the STIX loader/parser, or the SOC clients).
- Bypasses of the SOC write gate. State-changing SOC tools (`mitre_misp_create_event`, `mitre_thehive_create_case`, `mitre_cortex_run_analyzers`) must dry-run unless the caller passes `confirm: true` or sets `MITRE_SOC_ALLOW_WRITES`. A way to make them write without either is in scope.
- Bypasses of the SOC ID validation/encoding. User-supplied IDs are validated against strict allow-list patterns and URL-encoded before being interpolated into SOC API paths; a way to inject into those paths is in scope.
- Cases where disabling SSL verification for one integration (`*_VERIFY_SSL=false`) relaxes certificate validation for requests to other hosts. The relaxed TLS policy must stay scoped to the single integration's requests.
- Credentials, tokens, or internal hosts leaking from mitre-mcp's logs or tool output.

## Out of scope

- Vulnerabilities in MITRE's published ATT&CK STIX data itself.
- Vulnerabilities in Wazuh, TheHive, Cortex, MISP, or any client (Claude Code, OpenClaw, Hermes, Codex). Report those to their respective projects.
- Issues that require an attacker to already control the machine, the MCP client config, or the SOC credentials you supplied.
- The inherent risk of `mitre_cortex_run_analyzers` submitting live analyzer jobs against an observable you provided. That is the documented, gated behavior; confirm it deliberately.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated disclosure timeline can be negotiated for issues that need longer.
