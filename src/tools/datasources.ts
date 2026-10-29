import { referenceDataJson } from "../output.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";

export function registerDataSourceTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_get_datasource",
    "Get details on a data source and its components with detectable techniques",
    {
      dataSourceId: z
        .string()
        .optional()
        .describe('Data source ID (e.g., "DS0009")'),
      name: z
        .string()
        .optional()
        .describe('Data source name (e.g., "Process")'),
    },
    async ({ dataSourceId, name }) => {
      try {
        const lookup = dataSourceId || name;
        if (!lookup) {
          return {
            content: [
              {
                type: "text" as const,
                text: "Must provide either dataSourceId or name",
              },
            ],
            isError: true,
          };
        }

        const ds = store.getDataSource(lookup);
        if (!ds) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Data source "${lookup}" not found`,
              },
            ],
            isError: true,
          };
        }

        const components = store
          .getComponentsForDataSource(ds.stixId)
          .map((dc) => {
            const detects = store
              .getTechniquesDetectedByComponent(dc.stixId)
              .map((t) => ({ id: t.id, name: t.name }));
            return {
              name: dc.name,
              description: dc.description,
              detectedTechniques: detects,
            };
          });

        return {
          content: [
            {
              type: "text" as const,
              text: referenceDataJson(
                {
                  id: ds.id,
                  name: ds.name,
                  description: ds.description,
                  platforms: ds.platforms,
                  components,
                  references: ds.references,
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
    "mitre_detection_coverage",
    "Analyze detection coverage based on available data sources in your environment",
    {
      availableDataSources: z
        .array(z.string())
        .describe(
          "List of data source names you collect (e.g., ['Process', 'Network Traffic', 'File'])",
        ),
    },
    async ({ availableDataSources }) => {
      try {
        const allTechniques = store.getAllTechniques();
        const allTactics = store.getAllTactics();
        const allDataSources = store.getAllDataSources();
        const allComponents = store.getDataComponents();

        const availableNames = new Set(
          availableDataSources.map((n) => n.toLowerCase()),
        );

        // Find data source stix IDs that match available sources
        const availableDsStixIds = new Set(
          allDataSources
            .filter((ds) => availableNames.has(ds.name.toLowerCase()))
            .map((ds) => ds.stixId),
        );

        // Find components belonging to available data sources
        const availableComponentIds = new Set(
          allComponents
            .filter((dc) => availableDsStixIds.has(dc.dataSourceId))
            .map((dc) => dc.stixId),
        );

        // Find detectable techniques via relationships
        const detectableTechStixIds = new Set<string>();
        for (const rel of store.getRelationships()) {
          if (
            rel.relationshipType === "detects" &&
            availableComponentIds.has(rel.sourceRef)
          ) {
            detectableTechStixIds.add(rel.targetRef);
          }
        }

        const detectableTechniques = allTechniques.filter((t) =>
          detectableTechStixIds.has(t.stixId),
        );
        const detectableIds = new Set(detectableTechniques.map((t) => t.id));

        // Gap analysis by tactic
        const gapsByTactic = allTactics.map((tactic) => {
          const tacticTechs = store.getTechniquesForTactic(tactic.shortName);
          const covered = tacticTechs.filter((t) => detectableIds.has(t.id));
          const gaps = tacticTechs
            .filter((t) => !detectableIds.has(t.id))
            .map((t) => `${t.id} - ${t.name}`);

          return {
            tactic: tactic.name,
            coveredCount: covered.length,
            totalCount: tacticTechs.length,
            gaps: gaps.slice(0, 10),
          };
        });

        // Top gaps: techniques not covered
        const topGaps = allTechniques
          .filter((t) => !detectableIds.has(t.id) && !t.isSubtechnique)
          .slice(0, 20)
          .map((t) => ({
            technique: `${t.id} - ${t.name}`,
            tactics: t.tactics,
            dataSources: t.dataSources,
          }));

        // Recommendations
        const missingDsNames = allDataSources
          .filter((ds) => !availableNames.has(ds.name.toLowerCase()))
          .map((ds) => ds.name);

        const recommendations = missingDsNames.slice(0, 5).map(
          (name) => `Consider collecting "${name}" to improve coverage`,
        );

        const result = {
          totalTechniques: allTechniques.length,
          detectableTechniques: detectableTechniques.length,
          coveragePercentage: Math.round(
            (detectableTechniques.length / allTechniques.length) * 100,
          ),
          gapsByTactic,
          topGaps,
          recommendations,
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
}
