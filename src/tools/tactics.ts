import { referenceDataJson } from "../output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerTacticTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_list_tactics",
    "List all ATT&CK tactics in kill-chain order",
    {
      matrix: z
        .enum(["enterprise", "mobile", "ics"])
        .optional()
        .describe("ATT&CK matrix to list tactics for (default: enterprise)"),
    },
    async () => {
      try {
        const tactics = store.getAllTactics().map((t) => {
          const techniques = store.getTechniquesForTactic(t.shortName);
          return {
            id: t.id,
            name: t.name,
            shortName: t.shortName,
            description: t.description,
            techniqueCount: techniques.length,
          };
        });

        return {
          content: [
            { type: "text" as const, text: referenceDataJson(tactics, null, 2) },
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
    "mitre_get_tactic",
    "Get details and all techniques under a specific tactic",
    {
      tacticId: z
        .string()
        .describe(
          'Tactic ID (e.g., "TA0001") or short name (e.g., "initial-access")',
        ),
    },
    async ({ tacticId }) => {
      try {
        const tactic = store.getTactic(tacticId);
        if (!tactic) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Tactic ${tacticId} not found`,
              },
            ],
            isError: true,
          };
        }

        const techniques = store
          .getTechniquesForTactic(tactic.shortName)
          .map((t) => ({
            id: t.id,
            name: t.name,
            isSubtechnique: t.isSubtechnique,
            platforms: t.platforms,
          }));

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                {
                  id: tactic.id,
                  name: tactic.name,
                  shortName: tactic.shortName,
                  description: tactic.description,
                  techniqueCount: techniques.length,
                  techniques,
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
}
