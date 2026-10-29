import { referenceDataJson } from "./output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AttackDataStore } from "./data/index.js";
import { getLastUpdated } from "./data/loader.js";
import type { MitreConfig } from "./types.js";

export function registerResources(
  server: McpServer,
  store: AttackDataStore,
  config: MitreConfig,
): void {
  server.resource(
    "matrix-enterprise",
    "mitre://matrix/enterprise",
    {
      description: "Full ATT&CK Enterprise matrix (tactics x techniques)",
      mimeType: "application/json",
    },
    async () => {
      const tactics = store.getAllTactics();
      const matrix = tactics.map((tactic) => {
        const techniques = store
          .getTechniquesForTactic(tactic.shortName)
          .filter((t) => !t.isSubtechnique)
          .map((t) => ({
            id: t.id,
            name: t.name,
            subtechniques: store
              .getSubtechniques(t.id)
              .map((st) => ({ id: st.id, name: st.name })),
          }));

        return {
          tactic: { id: tactic.id, name: tactic.name, shortName: tactic.shortName },
          techniques,
        };
      });

      return {
        contents: [
          {
            uri: "mitre://matrix/enterprise",
            mimeType: "application/json",
            text: referenceDataJson(matrix, null, 2),
          },
        ],
      };
    },
  );

  server.resource(
    "version",
    "mitre://version",
    {
      description: "Current ATT&CK data version and statistics",
      mimeType: "application/json",
    },
    async () => {
      const stats = store.getStats();
      const lastUpdated = getLastUpdated(config.dataDir);

      return {
        contents: [
          {
            uri: "mitre://version",
            mimeType: "application/json",
            text: referenceDataJson(
              {
                matrices: config.matrices,
                lastUpdated: lastUpdated || "never",
                stats,
              },
              null,
              2,
            ),
          },
        ],
      };
    },
  );

  server.resource(
    "tactics",
    "mitre://tactics",
    {
      description: "All tactics in kill-chain order",
      mimeType: "application/json",
    },
    async () => {
      const tactics = store.getAllTactics().map((t) => ({
        id: t.id,
        name: t.name,
        shortName: t.shortName,
        description: t.description,
      }));

      return {
        contents: [
          {
            uri: "mitre://tactics",
            mimeType: "application/json",
            text: referenceDataJson(tactics, null, 2),
          },
        ],
      };
    },
  );
}
