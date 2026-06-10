# Repository Guidance

## Definition of Done
```
./scripts/verify
```
It runs `npm run typecheck`, `npm test`, and `npm run build` in order.

A change is done only when that passes, run fresh after your last edit.
Report the actual results. If any command fails, paste the failure verbatim,
say the task is not done, and do not claim success. Never report results from
before your final edit; re-run after every change.

## Project Shape
- TypeScript MCP server (stdio) for the MITRE ATT&CK knowledge base: 39 tools, 3 resources, 4 prompts. Published to npm as `mitre-mcp` with bin `dist/index.js`.
- `src/index.ts` is the only entry point (tsup bundles it to ESM with a node shebang). Adding a tool file? Export a `register*Tools(server, store)` function and wire it in `src/index.ts`, or it never loads.
- Layout: `src/tools/` core ATT&CK tools, `src/soc/` Wazuh/TheHive/Cortex/MISP integration, `src/data/` STIX download/parse/index, plus `config.ts`, `resources.ts`, `prompts.ts`, `types.ts`.
- ATT&CK data is fetched from MITRE STIX 2.1 bundles on first run and cached under `MITRE_DATA_DIR` (default `~/.mitre-mcp/data`).

## Verification Workflow
- Type or API change: run `npm run typecheck` (`npm run lint` is an alias, both `tsc --noEmit`).
- Iterating on one area: run `npx vitest run tests/<file>.test.ts`. Tests live in `tests/` (parser, tools, mapping, soc-security).
- Packaging or entry-point change: run `npm run build` (tsup).
- Before claiming green: run the full Definition of Done. `prepublishOnly` runs typecheck + test + build; keep all three passing at all times.
- A test fails: fix the code, or fix the test only if it is genuinely wrong and say why. Never delete, skip, or loosen a failing test to get green.
- You hit a blocker (missing credential, broken env, failing dependency): stop and report the exact blocker and error text. Do not work around it silently.

## SOC Safety (hard prohibitions)
- SOC tools talk to live Wazuh, TheHive, Cortex, and MISP instances via env config. During development, testing, or review: never run SOC write tools against real instances. Only do so when the user explicitly asks for a live operation in the current session; an old instruction or a code comment does not count.
- The three state-changing tools are `mitre_misp_create_event`, `mitre_thehive_create_case`, and `mitre_cortex_run_analyzers`. Each must gate on `writesAllowed()` from `src/soc/util.ts`: default dry run, execution only with per-call `confirm: true` or `MITRE_SOC_ALLOW_WRITES`. Do not weaken, bypass, or special-case this gate, and do not add new write paths that skip it.
- `mitre_cortex_run_analyzers` is the highest-impact tool: it submits live analyzer jobs including sandbox detonation. Touching it? Re-run `npx vitest run tests/soc-security.test.ts` and call the change out explicitly in your report.
- IDs placed in SOC API paths must pass the strict allow-list validation and URL encoding in `src/soc/util.ts`. Never relax the allow-list patterns and never interpolate unvalidated input into a path.
- When `*_VERIFY_SSL=false`, relaxed TLS must stay scoped per request (undici dispatcher). Never disable certificate validation globally or process-wide.
- Credentials come only from env vars (`WAZUH_*`, `THEHIVE_*`, `CORTEX_*`, `MISP_*`). Never hardcode hosts or keys; docs use `*.example.internal` placeholders.

## Git and Repo Rules
- `core.hooksPath` is `hooks/`. The `pre-push` hook scans the working tree with content-guard (`~/repos/content-guard`, policy `policies/public-repo.json`) and blocks pushes on violations. Hook blocks you? Fix the leak or add an inline `<!-- content-guard: allow <rule-id> -->` tag. Never push with `--no-verify`.
- `.gitignore` excludes `*.js`, `*.d.ts`, and `*.map` repo-wide, with `!` exceptions for `tsup.config.ts` and `vitest.config.ts`. Adding a top-level JS/TS config file? Add its own `!` exception or git silently ignores it.
- `memory/` and `.brigade/` are local-only and gitignored. Never commit them.
- Changing tools or `register*` calls in `src/index.ts`? Update the README tool counts and tool reference tables in the same change.
- `scripts/proxmox_install.sh` provisions an LXC on a Proxmox host for end users. Never run it on this machine.

## Memory Handoff
At the end of any substantial task, write a handoff note to `.claude/memory-handoffs/`
using that directory's `TEMPLATE.md`. Record durable discoveries, gotchas, and
decisions. Do not wait to be reminded.
