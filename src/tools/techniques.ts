import { referenceDataJson } from "../output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerTechniqueTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_get_technique",
    "Get full details of a specific ATT&CK technique by its ID (e.g., T1059, T1059.001)",
    {
      techniqueId: z
        .string()
        .describe("ATT&CK technique ID (e.g., T1059, T1059.001)"),
    },
    async ({ techniqueId }) => {
      try {
        const technique = store.getTechnique(techniqueId);
        if (!technique) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Technique ${techniqueId} not found`,
              },
            ],
            isError: true,
          };
        }

        const mitigations = store
          .getMitigationsForTechnique(technique.id)
          .map((m) => ({
            id: m.mitigation.id,
            name: m.mitigation.name,
            description: m.description,
          }));

        const subtechniques = store
          .getSubtechniques(technique.id)
          .map((t) => ({ id: t.id, name: t.name }));

        const parent = technique.parentId
          ? (() => {
              const p = store.getTechnique(technique.parentId);
              return p ? { id: p.id, name: p.name } : null;
            })()
          : null;

        // Get procedures (group/software usage)
        const procedures = store
          .getRelationships()
          .filter(
            (r) =>
              r.targetRef === technique.stixId &&
              r.relationshipType === "uses",
          )
          .slice(0, 20)
          .map((r) => ({ description: r.description }));

        const result = {
          id: technique.id,
          name: technique.name,
          tactics: technique.tactics,
          description: technique.description,
          platforms: technique.platforms,
          dataSources: technique.dataSources,
          detection: technique.detection,
          isSubtechnique: technique.isSubtechnique,
          deprecated: technique.deprecated,
          revoked: technique.revoked,
          mitigations,
          procedures,
          subtechniques,
          parent,
          references: technique.references,
        };

        return {
          content: [
            { type: "text" as const, text: referenceDataJson(result, null, 2) },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text" as const,
              text: "ATT&CK request failed.",
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_search_techniques",
    "Search ATT&CK techniques by keyword, tactic, platform, or data source",
    {
      query: z
        .string()
        .optional()
        .describe("Keyword search across technique name and description"),
      tactic: z
        .string()
        .optional()
        .describe(
          "Filter by tactic (e.g., initial-access, execution, persistence)",
        ),
      platform: z
        .string()
        .optional()
        .describe(
          "Filter by platform (e.g., Windows, Linux, macOS, Cloud)",
        ),
      dataSource: z.string().optional().describe("Filter by data source"),
      isSubtechnique: z
        .boolean()
        .optional()
        .describe("Filter parent techniques vs sub-techniques"),
    },
    async ({ query, tactic, platform, dataSource, isSubtechnique }) => {
      try {
        const results = store.searchTechniques({
          query,
          tactic,
          platform,
          dataSource,
          isSubtechnique,
        });

        const summary = results.slice(0, 50).map((t) => ({
          id: t.id,
          name: t.name,
          tactics: t.tactics,
          platforms: t.platforms,
          isSubtechnique: t.isSubtechnique,
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                { count: results.length, techniques: summary },
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
              text: "ATT&CK request failed.",
            },
          ],
          isError: true,
        };
      }
    },
  );
}
