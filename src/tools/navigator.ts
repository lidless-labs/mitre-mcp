import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";
import type { NavigatorLayer, NavigatorTechniqueEntry } from "../types.js";

const DEFAULT_GRADIENT = {
  colors: ["#ff6666ff", "#ffe766ff", "#8ec843ff"],
  minValue: 0,
  maxValue: 100,
};

function createBaseLayer(
  name: string,
  description: string,
  domain = "enterprise-attack",
): NavigatorLayer {
  return {
    name,
    versions: {
      attack: "16",
      navigator: "5.1.0",
      layer: "4.5",
    },
    domain,
    description,
    filters: { platforms: [] },
    sorting: 0,
    layout: {
      layout: "side",
      aggregateFunction: "average",
      showID: true,
      showName: true,
      showAggregateScores: false,
      countUnscored: false,
    },
    hideDisabled: false,
    techniques: [],
    gradient: DEFAULT_GRADIENT,
    legendItems: [],
    metadata: [],
    links: [],
    showTacticRowBackground: false,
    tacticRowBackground: "#dddddd",
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}

export function registerNavigatorTools(
  server: McpServer,
  store: AttackDataStore,
): void {
  server.tool(
    "mitre_navigator_layer",
    "Generate an ATT&CK Navigator layer JSON for visualization. Supports coverage heatmaps, group technique overlays, campaign views, and custom technique highlighting.",
    {
      mode: z
        .enum(["coverage", "group", "campaign", "techniques", "diff"])
        .describe(
          "Layer type: coverage (data source coverage), group (group techniques), campaign (observed techniques), techniques (custom list), diff (compare two groups)",
        ),
      name: z.string().optional().describe("Layer name"),
      dataSources: z
        .array(z.string())
        .optional()
        .describe("For coverage mode: available data source names"),
      groupId: z
        .string()
        .optional()
        .describe("For group mode: group ID or name"),
      techniques: z
        .array(z.string())
        .optional()
        .describe("For techniques/campaign mode: technique IDs"),
      compareGroupIds: z
        .array(z.string())
        .optional()
        .describe("For diff mode: two group IDs to compare"),
      color: z
        .string()
        .optional()
        .describe("Highlight color (default: #ff6666)"),
      showSubtechniques: z
        .boolean()
        .optional()
        .describe("Show sub-techniques (default: true)"),
    },
    async ({
      mode,
      name: layerName,
      dataSources,
      groupId,
      techniques,
      compareGroupIds,
      color,
      showSubtechniques,
    }) => {
      try {
        const showSubs = showSubtechniques !== false;

        switch (mode) {
          case "coverage": {
            if (!dataSources || dataSources.length === 0) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "dataSources required for coverage mode",
                  },
                ],
                isError: true,
              };
            }
            const layer = buildCoverageLayer(
              store,
              dataSources,
              layerName || "Detection Coverage",
              showSubs,
            );
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(layer, null, 2),
                },
              ],
            };
          }

          case "group": {
            if (!groupId) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "groupId required for group mode",
                  },
                ],
                isError: true,
              };
            }
            const group = store.getGroup(groupId);
            if (!group) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `Group "${groupId}" not found`,
                  },
                ],
                isError: true,
              };
            }
            const groupTechs = store
              .getGroupTechniques(group.stixId)
              .map((t) => t.technique);
            const layer = buildTechniqueLayer(
              groupTechs.map((t) => t.id),
              layerName || `${group.name} (${group.id})`,
              `Techniques used by ${group.name}`,
              color || "#ff6666",
              showSubs,
            );
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(layer, null, 2),
                },
              ],
            };
          }

          case "campaign":
          case "techniques": {
            if (!techniques || techniques.length === 0) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "techniques required for this mode",
                  },
                ],
                isError: true,
              };
            }
            const layer = buildTechniqueLayer(
              techniques,
              layerName || "Technique Overlay",
              mode === "campaign"
                ? "Observed campaign techniques"
                : "Custom technique selection",
              color || "#ff6666",
              showSubs,
            );
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(layer, null, 2),
                },
              ],
            };
          }

          case "diff": {
            if (!compareGroupIds || compareGroupIds.length < 2) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: "compareGroupIds (2 group IDs) required for diff mode",
                  },
                ],
                isError: true,
              };
            }
            const groupA = store.getGroup(compareGroupIds[0]);
            const groupB = store.getGroup(compareGroupIds[1]);
            if (!groupA || !groupB) {
              return {
                content: [
                  {
                    type: "text" as const,
                    text: `One or both groups not found: ${compareGroupIds.join(", ")}`,
                  },
                ],
                isError: true,
              };
            }
            const layer = buildDiffLayer(
              store,
              groupA,
              groupB,
              layerName ||
                `${groupA.name} vs ${groupB.name}`,
              showSubs,
            );
            return {
              content: [
                {
                  type: "text" as const,
                  text: JSON.stringify(layer, null, 2),
                },
              ],
            };
          }

          default:
            return {
              content: [
                { type: "text" as const, text: `Unknown mode: ${mode}` },
              ],
              isError: true,
            };
        }
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

function buildCoverageLayer(
  store: AttackDataStore,
  availableDataSources: string[],
  name: string,
  showSubs: boolean,
): NavigatorLayer {
  const layer = createBaseLayer(name, "Detection coverage based on available data sources");

  const availableNames = new Set(availableDataSources.map((n) => n.toLowerCase()));
  const allDataSources = store.getAllDataSources();
  const allComponents = store.getDataComponents();

  const availableDsStixIds = new Set(
    allDataSources
      .filter((ds) => availableNames.has(ds.name.toLowerCase()))
      .map((ds) => ds.stixId),
  );

  const availableComponentIds = new Set(
    allComponents
      .filter((dc) => availableDsStixIds.has(dc.dataSourceId))
      .map((dc) => dc.stixId),
  );

  const detectableTechStixIds = new Set<string>();
  for (const rel of store.getRelationships()) {
    if (
      rel.relationshipType === "detects" &&
      availableComponentIds.has(rel.sourceRef)
    ) {
      detectableTechStixIds.add(rel.targetRef);
    }
  }

  const allTechniques = store.getAllTechniques();
  for (const tech of allTechniques) {
    if (!showSubs && tech.isSubtechnique) continue;

    const detected = detectableTechStixIds.has(tech.stixId);
    const entry: NavigatorTechniqueEntry = {
      techniqueID: tech.id,
      color: detected ? "#8ec843" : "#ff6666",
      comment: detected ? "Covered" : "Gap",
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: showSubs,
      score: detected ? 100 : 0,
    };
    layer.techniques.push(entry);
  }

  layer.legendItems = [
    { label: "Covered", color: "#8ec843" },
    { label: "Gap", color: "#ff6666" },
  ];

  const total = layer.techniques.length;
  const covered = layer.techniques.filter((t) => t.score === 100).length;
  layer.metadata.push({
    name: "Coverage",
    value: `${covered}/${total} (${Math.round((covered / total) * 100)}%)`,
  });

  return layer;
}

function buildTechniqueLayer(
  techniqueIds: string[],
  name: string,
  description: string,
  highlightColor: string,
  showSubs: boolean,
): NavigatorLayer {
  const layer = createBaseLayer(name, description);

  const ids = new Set(techniqueIds.map((id) => id.toUpperCase()));

  for (const id of ids) {
    const entry: NavigatorTechniqueEntry = {
      techniqueID: id,
      color: highlightColor,
      comment: "",
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: showSubs,
    };
    layer.techniques.push(entry);
  }

  layer.legendItems = [{ label: name, color: highlightColor }];

  return layer;
}

function buildDiffLayer(
  store: AttackDataStore,
  groupA: { stixId: string; name: string; id: string },
  groupB: { stixId: string; name: string; id: string },
  name: string,
  showSubs: boolean,
): NavigatorLayer {
  const layer = createBaseLayer(
    name,
    `Technique comparison: ${groupA.name} vs ${groupB.name}`,
  );

  const techsA = new Set(
    store.getGroupTechniques(groupA.stixId).map((t) => t.technique.id),
  );
  const techsB = new Set(
    store.getGroupTechniques(groupB.stixId).map((t) => t.technique.id),
  );

  const allTechs = new Set([...techsA, ...techsB]);

  for (const id of allTechs) {
    const inA = techsA.has(id);
    const inB = techsB.has(id);

    let entryColor: string;
    let comment: string;

    if (inA && inB) {
      entryColor = "#ff66ff"; // Both
      comment = `Shared by ${groupA.name} and ${groupB.name}`;
    } else if (inA) {
      entryColor = "#ff6666"; // Only A
      comment = `${groupA.name} only`;
    } else {
      entryColor = "#6666ff"; // Only B
      comment = `${groupB.name} only`;
    }

    const entry: NavigatorTechniqueEntry = {
      techniqueID: id,
      color: entryColor,
      comment,
      enabled: true,
      metadata: [],
      links: [],
      showSubtechniques: showSubs,
    };
    layer.techniques.push(entry);
  }

  layer.legendItems = [
    { label: `${groupA.name} only`, color: "#ff6666" },
    { label: `${groupB.name} only`, color: "#6666ff" },
    { label: "Shared", color: "#ff66ff" },
  ];

  return layer;
}
