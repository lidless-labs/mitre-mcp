import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AttackDataStore } from "../data/index.js";
import type { MitreConfig } from "../types.js";
import { getLastUpdated } from "../data/loader.js";

export function registerManagementTools(
  server: McpServer,
  store: AttackDataStore,
  config: MitreConfig,
): void {
  server.tool(
    "mitre_update_data",
    "Force an update of the local ATT&CK data cache by re-downloading STIX bundles",
    {},
    async () => {
      try {
        await store.refresh();

        const stats = store.getStats();
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  status: "updated",
                  lastUpdated: new Date().toISOString(),
                  matrices: config.matrices,
                  stats,
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
              text: "ATT&CK data update failed. Check connectivity and cache access.",
            },
          ],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "mitre_data_version",
    "Get current ATT&CK data version, freshness, and object counts",
    {},
    async () => {
      try {
        const stats = store.getStats();
        const lastUpdated = getLastUpdated(config.dataDir);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
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
