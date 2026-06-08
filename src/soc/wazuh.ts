import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";
import type { WazuhClient } from "./client.js";
import { safePathSegment } from "./util.js";

// Mapping of Wazuh rule groups to ATT&CK tactic short names
const WAZUH_GROUP_TO_TACTIC: Record<string, string[]> = {
  authentication_failed: ["credential-access", "initial-access"],
  authentication_success: ["initial-access"],
  syslog: ["execution", "persistence"],
  firewall: ["command-and-control", "exfiltration"],
  web: ["initial-access", "execution"],
  windows: ["execution", "persistence", "privilege-escalation", "defense-evasion"],
  linux: ["execution", "persistence", "privilege-escalation"],
  ids: ["initial-access", "lateral-movement"],
  rootcheck: ["persistence", "privilege-escalation", "defense-evasion"],
  syscheck: ["persistence", "defense-evasion"],
  vulnerability_detector: ["initial-access"],
  osquery: ["discovery", "collection"],
  docker: ["execution", "privilege-escalation", "defense-evasion"],
  pam: ["credential-access", "persistence"],
  sshd: ["initial-access", "lateral-movement", "credential-access"],
  sudo: ["privilege-escalation"],
  audit: ["execution", "persistence", "privilege-escalation"],
  powershell: ["execution"],
  wmi: ["execution", "lateral-movement"],
  active_response: ["defense-evasion"],
};

// Common Wazuh rule ID ranges mapped to technique patterns
const WAZUH_RULE_TECHNIQUE_HINTS: Array<{
  ruleRange: [number, number];
  techniques: string[];
  description: string;
}> = [
  { ruleRange: [5501, 5599], techniques: ["T1110"], description: "PAM/SSH brute force" },
  { ruleRange: [5700, 5799], techniques: ["T1110", "T1021.004"], description: "SSH authentication" },
  { ruleRange: [18100, 18199], techniques: ["T1110"], description: "Windows logon failures" },
  { ruleRange: [60100, 60199], techniques: ["T1059.001"], description: "PowerShell events" },
  { ruleRange: [92000, 92099], techniques: ["T1055", "T1059"], description: "Sysmon process events" },
  { ruleRange: [92100, 92199], techniques: ["T1071", "T1573"], description: "Sysmon network events" },
  { ruleRange: [92200, 92299], techniques: ["T1547", "T1053"], description: "Sysmon registry/scheduled tasks" },
  { ruleRange: [80700, 80799], techniques: ["T1190", "T1133"], description: "Web attack patterns" },
  { ruleRange: [550, 599], techniques: ["T1565.001", "T1070"], description: "File integrity changes" },
  { ruleRange: [510, 549], techniques: ["T1543", "T1053"], description: "System service changes" },
  { ruleRange: [2500, 2599], techniques: ["T1046", "T1018"], description: "Firewall/IDS events" },
];

export function registerWazuhTools(
  server: McpServer,
  store: AttackDataStore,
  client: WazuhClient,
): void {
  server.tool(
    "mitre_wazuh_status",
    "Get Wazuh manager status, agent summary, and rule statistics",
    {},
    async () => {
      try {
        const [managerRes, agentsRes, rulesRes] = await Promise.all([
          client.request("GET", "/manager/status"),
          client.request("GET", "/agents/summary/status"),
          client.request("GET", "/rules/stats"),
        ]);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  manager: managerRes.data,
                  agents: agentsRes.data,
                  ruleStats: rulesRes.data,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_map_wazuh_alert",
    "Map a Wazuh alert (by rule ID, description, or groups) to ATT&CK techniques with confidence scoring",
    {
      ruleId: z
        .number()
        .optional()
        .describe("Wazuh rule ID"),
      ruleDescription: z
        .string()
        .optional()
        .describe("Wazuh rule description text"),
      ruleGroups: z
        .array(z.string())
        .optional()
        .describe("Wazuh rule groups (e.g., ['sshd', 'authentication_failed'])"),
      agentPlatform: z
        .string()
        .optional()
        .describe("Agent platform (windows, linux, macos)"),
    },
    async ({ ruleId, ruleDescription, ruleGroups, agentPlatform }) => {
      try {
        const matchedTechniques: Array<{
          id: string;
          name: string;
          confidence: number;
          reasons: string[];
          tactics: string[];
        }> = [];

        const allTechniques = store.getAllTechniques();
        const seenTechIds = new Set<string>();

        // 1. Match by rule ID range
        if (ruleId) {
          for (const hint of WAZUH_RULE_TECHNIQUE_HINTS) {
            if (ruleId >= hint.ruleRange[0] && ruleId <= hint.ruleRange[1]) {
              for (const techId of hint.techniques) {
                const tech = store.getTechnique(techId);
                if (tech && !seenTechIds.has(tech.id)) {
                  seenTechIds.add(tech.id);
                  matchedTechniques.push({
                    id: tech.id,
                    name: tech.name,
                    confidence: 85,
                    reasons: [`Rule ID ${ruleId} in range ${hint.ruleRange.join("-")} (${hint.description})`],
                    tactics: tech.tactics,
                  });
                }
              }
            }
          }
        }

        // 2. Match by rule groups to tactics, then find techniques
        if (ruleGroups && ruleGroups.length > 0) {
          const relevantTactics = new Set<string>();
          for (const group of ruleGroups) {
            const tactics = WAZUH_GROUP_TO_TACTIC[group.toLowerCase()];
            if (tactics) {
              for (const t of tactics) relevantTactics.add(t);
            }
          }

          if (relevantTactics.size > 0) {
            // Get techniques for matched tactics and score by keyword overlap
            for (const tactic of relevantTactics) {
              const tacticTechs = store.getTechniquesForTactic(tactic);
              for (const tech of tacticTechs.slice(0, 5)) {
                if (!seenTechIds.has(tech.id)) {
                  seenTechIds.add(tech.id);
                  matchedTechniques.push({
                    id: tech.id,
                    name: tech.name,
                    confidence: 40,
                    reasons: [`Rule groups [${ruleGroups.join(", ")}] map to tactic: ${tactic}`],
                    tactics: tech.tactics,
                  });
                }
              }
            }
          }
        }

        // 3. Keyword match on rule description
        if (ruleDescription) {
          const keywords = ruleDescription
            .toLowerCase()
            .split(/[\s,;:!?()[\]{}'"\/\\|@#$%^&*+=<>~`]+/)
            .filter((w) => w.length > 2)
            .filter(
              (w) =>
                !["the", "and", "for", "was", "with", "from", "that", "this", "are", "has", "have", "not", "but", "can", "rule", "alert", "event"].includes(w),
            );

          for (const tech of allTechniques) {
            if (seenTechIds.has(tech.id)) {
              // Boost existing match confidence
              const existing = matchedTechniques.find((m) => m.id === tech.id);
              if (existing) {
                for (const kw of keywords) {
                  if (tech.name.toLowerCase().includes(kw) || tech.description.toLowerCase().includes(kw)) {
                    existing.confidence = Math.min(existing.confidence + 15, 100);
                    existing.reasons.push(`Description keyword "${kw}" matches technique`);
                    break;
                  }
                }
              }
              continue;
            }

            let score = 0;
            const reasons: string[] = [];

            for (const kw of keywords) {
              if (tech.name.toLowerCase().includes(kw)) {
                score += 3;
                reasons.push(`Name matches "${kw}"`);
              }
              if (tech.detection.toLowerCase().includes(kw)) {
                score += 2;
                reasons.push(`Detection mentions "${kw}"`);
              }
              if (tech.description.toLowerCase().includes(kw)) {
                score += 1;
              }
            }

            if (agentPlatform && tech.platforms.some((p) => p.toLowerCase() === agentPlatform.toLowerCase())) {
              score += 1;
            }

            if (score >= 3) {
              seenTechIds.add(tech.id);
              matchedTechniques.push({
                id: tech.id,
                name: tech.name,
                confidence: Math.min(score * 10, 95),
                reasons: [...new Set(reasons)].slice(0, 5),
                tactics: tech.tactics,
              });
            }
          }
        }

        // Sort by confidence
        matchedTechniques.sort((a, b) => b.confidence - a.confidence);

        // Get mitigations for top matches
        const topMitigations = matchedTechniques
          .slice(0, 5)
          .flatMap((m) => {
            const mits = store.getMitigationsForTechnique(m.id);
            return mits.map((mit) => ({
              forTechnique: m.id,
              mitigationId: mit.mitigation.id,
              mitigationName: mit.mitigation.name,
            }));
          });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  input: { ruleId, ruleDescription, ruleGroups, agentPlatform },
                  matchCount: matchedTechniques.length,
                  matches: matchedTechniques.slice(0, 15),
                  suggestedMitigations: topMitigations,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_wazuh_rule_coverage",
    "Analyze Wazuh rules and map them to ATT&CK technique coverage. Shows which techniques your Wazuh deployment can detect.",
    {
      ruleGroup: z
        .string()
        .optional()
        .describe("Filter by Wazuh rule group (e.g., 'syscheck', 'sshd', 'windows')"),
      level: z
        .number()
        .optional()
        .describe("Minimum rule level to include (1-15)"),
    },
    async ({ ruleGroup, level }) => {
      try {
        // Fetch rules from Wazuh
        let path = "/rules?limit=500&offset=0";
        if (ruleGroup) path += `&group=${encodeURIComponent(ruleGroup)}`;
        if (level) path += `&min_level=${level}`;

        const rulesRes = await client.request<{
          data?: {
            affected_items?: Array<{
              id: number;
              description: string;
              groups: string[];
              level: number;
              mitre?: { id?: string[]; tactic?: string[] };
            }>;
            total_affected_items?: number;
          };
        }>("GET", path);

        if (!rulesRes.ok || !rulesRes.data) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to fetch Wazuh rules: ${rulesRes.error || "Unknown error"}`,
              },
            ],
            isError: true,
          };
        }

        const rules = rulesRes.data.data?.affected_items || [];
        const totalRules = rulesRes.data.data?.total_affected_items || rules.length;

        // Count rules with MITRE mappings
        const mappedRules: Array<{
          ruleId: number;
          description: string;
          level: number;
          mitreIds: string[];
          mitreTactics: string[];
        }> = [];

        const techniqueCoverage = new Map<string, number>();
        const tacticCoverage = new Map<string, number>();

        for (const rule of rules) {
          if (rule.mitre?.id && rule.mitre.id.length > 0) {
            mappedRules.push({
              ruleId: rule.id,
              description: rule.description,
              level: rule.level,
              mitreIds: rule.mitre.id,
              mitreTactics: rule.mitre.tactic || [],
            });

            for (const techId of rule.mitre.id) {
              techniqueCoverage.set(techId, (techniqueCoverage.get(techId) || 0) + 1);
            }
            for (const tactic of rule.mitre.tactic || []) {
              tacticCoverage.set(tactic, (tacticCoverage.get(tactic) || 0) + 1);
            }
          }
        }

        // Cross-reference with ATT&CK store
        const allTechniques = store.getAllTechniques().filter((t) => !t.isSubtechnique);
        const coveredTechIds = new Set(techniqueCoverage.keys());
        const gaps = allTechniques
          .filter((t) => !coveredTechIds.has(t.id))
          .slice(0, 20)
          .map((t) => ({ id: t.id, name: t.name, tactics: t.tactics }));

        // Sort technique coverage by rule count
        const topCovered = [...techniqueCoverage.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 20)
          .map(([techId, ruleCount]) => {
            const tech = store.getTechnique(techId);
            return {
              techniqueId: techId,
              techniqueName: tech?.name || "Unknown",
              wazuhRuleCount: ruleCount,
            };
          });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  totalWazuhRules: totalRules,
                  rulesWithMitreMapping: mappedRules.length,
                  uniqueTechniquesCovered: techniqueCoverage.size,
                  totalAttackTechniques: allTechniques.length,
                  coveragePercentage: Math.round(
                    (techniqueCoverage.size / allTechniques.length) * 100,
                  ),
                  tacticCoverage: Object.fromEntries(tacticCoverage),
                  topCoveredTechniques: topCovered,
                  topGaps: gaps,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_wazuh_alerts",
    "Fetch recent Wazuh alerts and enrich them with ATT&CK context",
    {
      limit: z.number().optional().describe("Number of alerts to fetch (default: 10, max: 100)"),
      level: z.number().optional().describe("Minimum alert level (1-15)"),
      agentId: z.string().optional().describe("Filter by agent ID"),
      search: z.string().optional().describe("Search term in alert descriptions"),
    },
    async ({ limit, level, agentId, search }) => {
      try {
        const n = Math.min(limit || 10, 100);
        let path = `/alerts?limit=${n}&sort=-timestamp`;
        if (level) path += `&min_level=${level}`;
        if (agentId) path += `&agent_id=${safePathSegment(agentId, "agentId")}`;
        if (search) path += `&search=${encodeURIComponent(search)}`;

        const res = await client.request<{
          data?: {
            affected_items?: Array<{
              id: string;
              timestamp: string;
              rule: {
                id: number;
                description: string;
                level: number;
                groups: string[];
                mitre?: { id?: string[]; tactic?: string[] };
              };
              agent: { id: string; name: string };
              data?: Record<string, unknown>;
            }>;
          };
        }>("GET", path);

        if (!res.ok || !res.data) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to fetch alerts: ${res.error || "Unknown error"}`,
              },
            ],
            isError: true,
          };
        }

        const alerts = res.data.data?.affected_items || [];

        const enriched = alerts.map((alert) => {
          const mitreIds = alert.rule.mitre?.id || [];
          const enrichment = mitreIds.map((techId) => {
            const tech = store.getTechnique(techId);
            if (!tech) return { id: techId, found: false };
            const mits = store.getMitigationsForTechnique(techId);
            return {
              id: tech.id,
              name: tech.name,
              tactics: tech.tactics,
              found: true,
              mitigations: mits.slice(0, 3).map((m) => ({
                id: m.mitigation.id,
                name: m.mitigation.name,
              })),
            };
          });

          return {
            alertId: alert.id,
            timestamp: alert.timestamp,
            agent: alert.agent,
            rule: {
              id: alert.rule.id,
              description: alert.rule.description,
              level: alert.rule.level,
              groups: alert.rule.groups,
            },
            attackContext: enrichment,
          };
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { alertCount: enriched.length, alerts: enriched },
                null,
                2,
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Error: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
