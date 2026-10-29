import { referenceDataJson } from "../output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerMitigationTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_get_mitigation",
    "Get details on a mitigation and all techniques it addresses",
    {
      mitigationId: z
        .string()
        .describe('Mitigation ID (e.g., "M1036")'),
    },
    async ({ mitigationId }) => {
      try {
        const mitigation = store.getMitigation(mitigationId);
        if (!mitigation) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Mitigation ${mitigationId} not found`,
              },
            ],
            isError: true,
          };
        }

        const techniques = store
          .getTechniquesForMitigation(mitigation.id)
          .map((t) => ({
            id: t.technique.id,
            name: t.technique.name,
            description: t.description,
          }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                {
                  id: mitigation.id,
                  name: mitigation.name,
                  description: mitigation.description,
                  techniques,
                  references: mitigation.references,
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
              text: "ATT&CK request failed.",
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_mitigations_for_technique",
    "Get all mitigations applicable to a specific technique",
    {
      techniqueId: z
        .string()
        .describe("ATT&CK technique ID (e.g., T1059.001)"),
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
            mitigationDescription: m.mitigation.description,
            implementationGuidance: m.description,
          }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                {
                  techniqueId: technique.id,
                  techniqueName: technique.name,
                  mitigations,
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
              text: "ATT&CK request failed.",
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_search_mitigations",
    "Search mitigations by keyword",
    {
      query: z.string().describe("Keyword search for mitigations"),
    },
    async ({ query }) => {
      try {
        const results = store.searchMitigations(query);

        const summary = results.slice(0, 50).map((m) => ({
          id: m.id,
          name: m.name,
          description: m.description.slice(0, 200),
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                { count: results.length, mitigations: summary },
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
