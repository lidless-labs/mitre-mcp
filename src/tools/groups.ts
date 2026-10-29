import { referenceDataJson } from "../output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerGroupTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_get_group",
    "Get details on a known threat group/APT including techniques and software used",
    {
      groupId: z
        .string()
        .optional()
        .describe('Group ID (e.g., "G0016")'),
      name: z
        .string()
        .optional()
        .describe('Group name or alias (e.g., "APT28")'),
    },
    async ({ groupId, name }) => {
      try {
        const lookup = groupId || name;
        if (!lookup) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Must provide either groupId or name",
              },
            ],
            isError: true,
          };
        }

        const group = store.getGroup(lookup);
        if (!group) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Group "${lookup}" not found`,
              },
            ],
            isError: true,
          };
        }

        const techniques = store
          .getGroupTechniques(group.stixId)
          .map((t) => ({
            id: t.technique.id,
            name: t.technique.name,
            usage: t.usage,
          }));

        const software = store
          .getGroupSoftware(group.stixId)
          .map((s) => ({
            id: s.software.id,
            name: s.software.name,
          }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                {
                  id: group.id,
                  name: group.name,
                  aliases: group.aliases,
                  description: group.description,
                  techniques,
                  software,
                  references: group.references,
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
    "mitre_search_groups",
    "Search threat groups by keyword or by technique usage",
    {
      query: z
        .string()
        .optional()
        .describe("Keyword search across group name, aliases, description"),
      technique: z
        .string()
        .optional()
        .describe("Find groups using a specific technique ID"),
    },
    async ({ query, technique }) => {
      try {
        const results = store.searchGroups({ query, technique });

        const summary = results.slice(0, 50).map((g) => ({
          id: g.id,
          name: g.name,
          aliases: g.aliases,
          description: g.description.slice(0, 200),
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                { count: results.length, groups: summary },
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
    "mitre_list_groups",
    "List all known threat groups with names, aliases, and brief descriptions",
    {},
    async () => {
      try {
        const groups = store.getAllGroups().map((g) => ({
          id: g.id,
          name: g.name,
          aliases: g.aliases,
          description: g.description.slice(0, 200),
        }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                { count: groups.length, groups },
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
