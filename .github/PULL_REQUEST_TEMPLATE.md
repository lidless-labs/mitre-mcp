<!--
Thanks for sending a patch. Keep this short; delete sections that do not apply.
See CONTRIBUTING.md for what lands easily and what needs an issue first.
-->

## What and why

<!-- One or two sentences on the user-visible change and the problem it solves. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New ATT&CK tool / resource / prompt
- [ ] SOC client robustness or docs
- [ ] Refactor with no tool-surface change
- [ ] Surface change (new SOC integration, or breaking change to tool names/schemas/URIs) — opened an issue first per CONTRIBUTING.md

## Checklist

- [ ] `./scripts/verify` passes locally (typecheck, tests, build)
- [ ] Added or updated tests covering the change
- [ ] Updated the `Unreleased` section of `CHANGELOG.md` for any user-visible effect
- [ ] Updated the tool/resource/prompt tables in `README.md` if the surface changed
- [ ] No personal details, real hostnames, real private IPs, account names, tokens, or unredacted absolute paths in code, tests, or docs (example hosts use the RFC 5737 `192.0.2.x` range; the content-guard hook and CI will fail otherwise)
- [ ] Any state-changing SOC tool still routes through the `confirm` / `MITRE_SOC_ALLOW_WRITES` write gate
- [ ] Conventional commit messages, no AI co-authorship trailers
