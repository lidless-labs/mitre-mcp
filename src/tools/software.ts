import { referenceDataJson } from "../output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerSoftwareTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_get_software",
    "Get details on a known software, malware, or tool including techniques and associated groups",
    {
      softwareId: z
        .string()
        .optional()
        .describe('Software ID (e.g., "S0154")'),
      name: z
        .string()
        .optional()
        .describe('Software name (e.g., "Cobalt Strike")'),
    },
    async ({ softwareId, name }) => {
      try {
        const lookup = softwareId || name;
        if (!lookup) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Must provide either softwareId or name",
              },
            ],
            isError: true,
          };
        }

        const sw = store.getSoftware(lookup);
        if (!sw) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Software "${lookup}" not found`,
              },
            ],
            isError: true,
          };
        }

        const techniques = store
          .getSoftwareTechniques(sw.stixId)
          .map((t) => ({
            id: t.technique.id,
            name: t.technique.name,
            usage: t.usage,
          }));

        const groups = store.getSoftwareGroups(sw.stixId).map((g) => ({
          id: g.group.id,
          name: g.group.name,
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                {
                  id: sw.id,
                  name: sw.name,
                  type: sw.type,
                  aliases: sw.aliases,
                  description: sw.description,
                  platforms: sw.platforms,
                  techniques,
                  groups,
                  references: sw.references,
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
    "mitre_search_software",
    "Search software/malware by name, keyword, technique, or type",
    {
      query: z
        .string()
        .optional()
        .describe("Keyword search across software name and description"),
      technique: z
        .string()
        .optional()
        .describe("Find software using a specific technique ID"),
      type: z
        .enum(["malware", "tool"])
        .optional()
        .describe("Filter by software type"),
    },
    async ({ query, technique, type }) => {
      try {
        const results = store.searchSoftware({ query, technique, type });

        const summary = results.slice(0, 50).map((s) => ({
          id: s.id,
          name: s.name,
          type: s.type,
          aliases: s.aliases,
          platforms: s.platforms,
          description: s.description.slice(0, 200),
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                { count: results.length, software: summary },
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
