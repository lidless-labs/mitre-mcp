import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { externalDataJson } from "../soc/util.js";
import type { AttackDataStore } from "../data/index.js";

export function registerMappingTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_map_alert_to_technique",
    "Map a security alert or observable to likely ATT&CK techniques with confidence scoring",
    {
      alertType: z
        .string()
        .describe(
          'Description of the alert (e.g., "PowerShell encoded command execution")',
        ),
      indicators: z
        .array(z.string())
        .optional()
        .describe("Associated indicators (IPs, domains, file hashes, process names)"),
      platform: z
        .string()
        .optional()
        .describe("Target platform (e.g., Windows, Linux)"),
    },
    async ({ alertType, indicators, platform }) => {
      try {
        const keywords = extractKeywords(alertType, indicators || []);
        const allTechniques = store.getAllTechniques();

        const scored = allTechniques
          .map((t) => {
            let score = 0;
            const reasons: string[] = [];

            // Score based on keyword matches in name
            for (const kw of keywords) {
              if (t.name.toLowerCase().includes(kw)) {
                score += 3;
                reasons.push(`Name matches "${kw}"`);
              }
            }

            // Score based on keyword matches in description
            for (const kw of keywords) {
              if (t.description.toLowerCase().includes(kw)) {
                score += 1;
                reasons.push(`Description mentions "${kw}"`);
              }
            }

            // Score based on keyword matches in detection
            for (const kw of keywords) {
              if (t.detection.toLowerCase().includes(kw)) {
                score += 2;
                reasons.push(`Detection guidance mentions "${kw}"`);
              }
            }

            // Platform match bonus
            if (
              platform &&
              t.platforms.some(
                (p) => p.toLowerCase() === platform.toLowerCase(),
              )
            ) {
              score += 1;
              reasons.push(`Platform match: ${platform}`);
            }

            return { technique: t, score, reasons };
          })
          .filter((r) => r.score > 0)
          .sort((a, b) => b.score - a.score)
          .slice(0, 15);

        const maxScore = scored[0]?.score || 1;
        const results = scored.map((r) => ({
          id: r.technique.id,
          name: r.technique.name,
          tactics: r.technique.tactics,
          confidence: Math.min(Math.round((r.score / maxScore) * 100), 100),
          reasons: [...new Set(r.reasons)].slice(0, 5),
          platforms: r.technique.platforms,
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: externalDataJson(
                { alertType, matchCount: results.length, matches: results },
                "Caller-supplied alert data",
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
    "mitre_technique_overlap",
    "Find technique overlap between threat groups for attribution assistance",
    {
      groupIds: z
        .array(z.string())
        .optional()
        .describe("Group IDs to compare"),
      techniques: z
        .array(z.string())
        .optional()
        .describe("Technique IDs to find groups sharing these techniques"),
    },
    async ({ groupIds, techniques }) => {
      try {
        if (groupIds && groupIds.length >= 2) {
          // Compare technique sets between specified groups
          const groupTechSets: Array<{
            id: string;
            name: string;
            techniques: Set<string>;
          }> = [];

          for (const gid of groupIds) {
            const group = store.getGroup(gid);
            if (!group) continue;
            const techs = store
              .getGroupTechniques(group.stixId)
              .map((t) => t.technique.id);
            groupTechSets.push({
              id: group.id,
              name: group.name,
              techniques: new Set(techs),
            });
          }

          const overlaps: Array<{
            groups: string[];
            sharedTechniques: string[];
            overlapScore: number;
          }> = [];

          for (let i = 0; i < groupTechSets.length; i++) {
            for (let j = i + 1; j < groupTechSets.length; j++) {
              const a = groupTechSets[i];
              const b = groupTechSets[j];
              const shared = [...a.techniques].filter((t) =>
                b.techniques.has(t),
              );
              const union = new Set([...a.techniques, ...b.techniques]);
              overlaps.push({
                groups: [`${a.id} (${a.name})`, `${b.id} (${b.name})`],
                sharedTechniques: shared,
                overlapScore: Math.round((shared.length / union.size) * 100),
              });
            }
          }

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ overlaps }, null, 2),
              },
            ],
          };
        }

        if (techniques && techniques.length > 0) {
          // Find groups that use the given techniques
          const techSet = new Set(techniques.map((t) => t.toUpperCase()));
          const allGroups = store.getAllGroups();

          const matches = allGroups
            .map((group) => {
              const groupTechs = store
                .getGroupTechniques(group.stixId)
                .map((t) => t.technique.id);
              const shared = groupTechs.filter((t) => techSet.has(t));
              return {
                id: group.id,
                name: group.name,
                sharedTechniques: shared,
                overlapScore: Math.round(
                  (shared.length / techSet.size) * 100,
                ),
              };
            })
            .filter((m) => m.sharedTechniques.length > 0)
            .sort((a, b) => b.overlapScore - a.overlapScore)
            .slice(0, 15);

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  { inputTechniques: techniques, matches },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: "text" as const,
              text: "Must provide either groupIds (2+) or techniques (1+)",
            },
          ],
          isError: true,
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
    "mitre_attack_path",
    "Generate possible attack paths through the kill chain starting from a technique",
    {
      startTechnique: z
        .string()
        .describe("Starting technique ID"),
      targetTactic: z
        .string()
        .optional()
        .describe("Target tactic to reach (e.g., exfiltration)"),
    },
    async ({ startTechnique, targetTactic }) => {
      try {
        const startTech = store.getTechnique(startTechnique);
        if (!startTech) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Technique ${startTechnique} not found`,
              },
            ],
            isError: true,
          };
        }

        const tacticOrder = store.getAllTactics();
        const startTacticNames = startTech.tactics;

        // Find the earliest tactic position of the start technique
        const startOrder = Math.min(
          ...startTacticNames.map((t) => {
            const tactic = tacticOrder.find(
              (ta) => ta.shortName === t,
            );
            return tactic?.order ?? 99;
          }),
        );

        // Build path by selecting techniques from subsequent tactics
        const path: Array<{
          tactic: string;
          techniques: Array<{ id: string; name: string }>;
        }> = [];

        for (const tactic of tacticOrder) {
          if (tactic.order < startOrder) continue;
          if (targetTactic && tactic.order > (tacticOrder.find(
            (t) => t.shortName === targetTactic,
          )?.order ?? 99)) {
            break;
          }

          const techs = store.getTechniquesForTactic(tactic.shortName);
          // Pick representative techniques (non-subtechniques, top 3)
          const representative = techs
            .filter((t) => !t.isSubtechnique)
            .slice(0, 3)
            .map((t) => ({ id: t.id, name: t.name }));

          path.push({
            tactic: `${tactic.name} (${tactic.shortName})`,
            techniques: representative,
          });
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  startTechnique: {
                    id: startTech.id,
                    name: startTech.name,
                    tactics: startTech.tactics,
                  },
                  targetTactic: targetTactic || "end of kill chain",
                  path,
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
}

function extractKeywords(
  alertType: string,
  indicators: string[],
): string[] {
  const text = [alertType, ...indicators].join(" ").toLowerCase();
  const words = text
    .split(/[\s,;:!?()[\]{}'"\/\\|@#$%^&*+=<>~`]+/)
    .filter((w) => w.length > 2)
    .filter(
      (w) =>
        ![
          "the",
          "and",
          "for",
          "was",
          "with",
          "from",
          "that",
          "this",
          "are",
          "has",
          "have",
          "not",
          "but",
          "can",
        ].includes(w),
    );
  return [...new Set(words)];
}
