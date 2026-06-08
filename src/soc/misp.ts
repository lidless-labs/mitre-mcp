import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";
import type { MispClient } from "./client.js";
import { safePathSegment, writesAllowed } from "./util.js";

export function registerMispTools(
  server: McpServer,
  store: AttackDataStore,
  client: MispClient,
): void {
  server.tool(
    "mitre_misp_event_to_attack",
    "Map a MISP event's attributes and galaxies to ATT&CK techniques, providing full technique context and mitigation recommendations",
    {
      eventId: z.string().describe("MISP event ID"),
    },
    async ({ eventId }) => {
      try {
        const safeEventId = safePathSegment(eventId, "eventId");
        const res = await client.request<{
          Event?: {
            id: string;
            info: string;
            date: string;
            threat_level_id: string;
            analysis: string;
            Tag?: Array<{ name: string }>;
            Attribute?: Array<{
              id: string;
              type: string;
              category: string;
              value: string;
              comment: string;
              to_ids: boolean;
            }>;
            Galaxy?: Array<{
              name: string;
              type: string;
              GalaxyCluster?: Array<{
                value: string;
                tag_name: string;
                description: string;
                meta?: {
                  external_id?: string[];
                  mitre_attack_id?: string;
                };
              }>;
            }>;
            Object?: Array<{
              name: string;
              Attribute?: Array<{
                type: string;
                value: string;
                object_relation: string;
              }>;
            }>;
          };
        }>("GET", `/events/view/${safeEventId}`);

        if (!res.ok || !res.data?.Event) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to fetch MISP event ${eventId}: ${res.error || `HTTP ${res.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const event = res.data.Event;

        // Extract ATT&CK technique IDs from galaxies
        const galaxyTechniques: Array<{
          id: string;
          galaxyName: string;
          clusterValue: string;
        }> = [];

        for (const galaxy of event.Galaxy || []) {
          if (
            galaxy.type === "mitre-attack-pattern" ||
            galaxy.name.toLowerCase().includes("att&ck") ||
            galaxy.name.toLowerCase().includes("attack")
          ) {
            for (const cluster of galaxy.GalaxyCluster || []) {
              // Extract technique ID from tag name or external_id
              let techId: string | null = null;

              if (cluster.meta?.external_id?.[0]) {
                techId = cluster.meta.external_id[0];
              } else if (cluster.meta?.mitre_attack_id) {
                techId = cluster.meta.mitre_attack_id;
              } else {
                // Try to extract from tag name like "misp-galaxy:mitre-attack-pattern=\"T1059 - Command and Scripting Interpreter\""
                const match = cluster.tag_name?.match(/T\d{4}(?:\.\d{3})?/);
                if (match) techId = match[0];
              }

              if (techId) {
                galaxyTechniques.push({
                  id: techId,
                  galaxyName: galaxy.name,
                  clusterValue: cluster.value,
                });
              }
            }
          }
        }

        // Extract technique IDs from tags
        const tagTechniques: string[] = [];
        for (const tag of event.Tag || []) {
          const match = tag.name.match(/T\d{4}(?:\.\d{3})?/);
          if (match) tagTechniques.push(match[0]);
        }

        // Combine all found technique IDs
        const allTechIds = new Set([
          ...galaxyTechniques.map((g) => g.id),
          ...tagTechniques,
        ]);

        // Resolve against ATT&CK store
        const resolvedTechniques = [...allTechIds]
          .map((id) => {
            const tech = store.getTechnique(id);
            if (!tech) return null;
            const mits = store.getMitigationsForTechnique(id);
            return {
              id: tech.id,
              name: tech.name,
              tactics: tech.tactics,
              platforms: tech.platforms,
              mitigations: mits.slice(0, 3).map((m) => ({
                id: m.mitigation.id,
                name: m.mitigation.name,
              })),
            };
          })
          .filter((t): t is NonNullable<typeof t> => t !== null);

        // Also keyword-match attributes against techniques
        const attributes = event.Attribute || [];
        const iocs = attributes
          .filter((a) => a.to_ids)
          .map((a) => ({
            type: a.type,
            category: a.category,
            value: a.value,
            comment: a.comment,
          }));

        // Map attribute types to data sources
        const dataSourceHints: Record<string, string[]> = {
          ip: ["Network Traffic"],
          "ip-src": ["Network Traffic"],
          "ip-dst": ["Network Traffic"],
          domain: ["Network Traffic"],
          hostname: ["Network Traffic"],
          url: ["Network Traffic"],
          "user-agent": ["Network Traffic"],
          filename: ["File"],
          md5: ["File"],
          sha1: ["File"],
          sha256: ["File"],
          "email-src": ["Network Traffic"],
          "email-subject": ["Network Traffic"],
          "registry-key": ["Windows Registry"],
          mutex: ["Process"],
          "process-name": ["Process"],
        };

        const suggestedDataSources = new Set<string>();
        for (const attr of attributes) {
          const hints = dataSourceHints[attr.type];
          if (hints) {
            for (const h of hints) suggestedDataSources.add(h);
          }
        }

        // Find likely groups
        const groupMatches = resolvedTechniques.length > 0
          ? store
              .getAllGroups()
              .map((group) => {
                const groupTechs = store
                  .getGroupTechniques(group.stixId)
                  .map((t) => t.technique.id);
                const shared = groupTechs.filter((t) => allTechIds.has(t));
                return {
                  id: group.id,
                  name: group.name,
                  overlapCount: shared.length,
                  sharedTechniques: shared,
                };
              })
              .filter((m) => m.overlapCount > 0)
              .sort((a, b) => b.overlapCount - a.overlapCount)
              .slice(0, 5)
          : [];

        const threatLevel = ["", "High", "Medium", "Low", "Undefined"][
          parseInt(event.threat_level_id) || 4
        ];

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  eventId: event.id,
                  eventInfo: event.info,
                  eventDate: event.date,
                  threatLevel,
                  attributeCount: attributes.length,
                  iocCount: iocs.length,
                  galaxyTechniqueCount: galaxyTechniques.length,
                  tagTechniqueCount: tagTechniques.length,
                  resolvedTechniques,
                  iocs: iocs.slice(0, 20),
                  likelyThreatGroups: groupMatches,
                  suggestedDataSources: [...suggestedDataSources],
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

  server.tool(
    "mitre_misp_search_indicators",
    "Search MISP for indicators (IOCs) related to specific ATT&CK techniques or threat groups",
    {
      techniqueId: z
        .string()
        .optional()
        .describe("ATT&CK technique ID to find related MISP indicators for"),
      groupName: z
        .string()
        .optional()
        .describe("Threat group name to find related MISP events for"),
      indicatorType: z
        .string()
        .optional()
        .describe("MISP attribute type filter (ip-src, domain, md5, sha256, url, etc.)"),
      limit: z
        .number()
        .optional()
        .describe("Maximum results (default: 25)"),
    },
    async ({ techniqueId, groupName, indicatorType, limit }) => {
      try {
        const searchBody: Record<string, unknown> = {
          returnFormat: "json",
          limit: limit || 25,
          enforceWarninglist: true,
        };

        // Build search tags
        const tags: string[] = [];

        if (techniqueId) {
          const tech = store.getTechnique(techniqueId);
          if (tech) {
            // MISP galaxy tags for ATT&CK techniques
            tags.push(`misp-galaxy:mitre-attack-pattern="${tech.id} - ${tech.name}"`);
          }
          searchBody.tags = tags;
        }

        if (groupName) {
          const group = store.getGroup(groupName);
          if (group) {
            tags.push(`misp-galaxy:mitre-intrusion-set="${group.name}"`);
          }
          searchBody.tags = tags;
        }

        if (indicatorType) {
          searchBody.type = indicatorType;
        }

        const res = await client.request<{
          response?: {
            Attribute?: Array<{
              id: string;
              event_id: string;
              type: string;
              category: string;
              value: string;
              comment: string;
              to_ids: boolean;
              timestamp: string;
              Tag?: Array<{ name: string }>;
            }>;
          };
        }>("POST", "/attributes/restSearch", searchBody);

        if (!res.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `MISP search failed: ${res.error || `HTTP ${res.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const attributes = res.data?.response?.Attribute || [];

        const results = attributes.map((attr) => {
          // Extract any ATT&CK tags
          const attackTags = (attr.Tag || [])
            .map((t) => t.name)
            .filter((n) => n.match(/T\d{4}/))
            .map((n) => {
              const match = n.match(/T\d{4}(?:\.\d{3})?/);
              return match ? match[0] : null;
            })
            .filter((t): t is string => t !== null);

          return {
            id: attr.id,
            eventId: attr.event_id,
            type: attr.type,
            category: attr.category,
            value: attr.value,
            comment: attr.comment,
            isIoc: attr.to_ids,
            relatedTechniques: attackTags,
          };
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  searchCriteria: { techniqueId, groupName, indicatorType },
                  resultCount: results.length,
                  indicators: results,
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

  server.tool(
    "mitre_misp_create_event",
    "Create a MISP event pre-tagged with ATT&CK techniques and threat group galaxies",
    {
      info: z.string().describe("Event title/info"),
      techniques: z
        .array(z.string())
        .describe("ATT&CK technique IDs to tag"),
      threatLevel: z
        .enum(["high", "medium", "low"])
        .optional()
        .describe("Threat level (default: medium)"),
      distribution: z
        .number()
        .optional()
        .describe("Distribution (0=org, 1=community, 2=connected, 3=all, default: 0)"),
      attributes: z
        .array(
          z.object({
            type: z.string().describe("Attribute type (ip-src, domain, md5, sha256, url, etc.)"),
            value: z.string().describe("Attribute value"),
            category: z.string().optional().describe("Category (e.g., Network activity, Payload delivery)"),
            toIds: z.boolean().optional().describe("Mark as IOC for IDS export"),
            comment: z.string().optional(),
          }),
        )
        .optional()
        .describe("Attributes/IOCs to add"),
      confirm: z
        .boolean()
        .optional()
        .describe(
          "Must be true to actually create the event in MISP. Defaults to false (dry-run: returns the event that would be created without writing). Can also be globally enabled via MITRE_SOC_ALLOW_WRITES.",
        ),
    },
    async ({ info, techniques, threatLevel, distribution, attributes, confirm }) => {
      try {
        const resolvedTechs = techniques
          .map((id) => store.getTechnique(id))
          .filter((t): t is NonNullable<typeof t> => !!t);

        const threatLevelId = { high: "1", medium: "2", low: "3" }[
          threatLevel || "medium"
        ];

        // Write guard: skip the live MISP mutation unless explicitly confirmed.
        if (!writesAllowed(confirm)) {
          const tactics = [...new Set(resolvedTechs.flatMap((t) => t.tactics))];
          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    dryRun: true,
                    message:
                      "Dry run: no event created. Set confirm=true (or MITRE_SOC_ALLOW_WRITES=true) to create.",
                    wouldCreate: {
                      info,
                      threatLevel: threatLevel || "medium",
                      distribution: distribution ?? 0,
                      techniquesToTag: resolvedTechs.map((t) => t.id),
                      tacticsToTag: tactics,
                      attributesToAdd: (attributes || []).map(
                        (a) => `${a.type}: ${a.value}`,
                      ),
                    },
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // Create event
        const eventRes = await client.request<{
          Event?: { id: string; uuid: string; info: string };
        }>("POST", "/events/add", {
          Event: {
            info,
            threat_level_id: threatLevelId,
            distribution: distribution ?? 0,
            analysis: "0", // Initial
            date: new Date().toISOString().split("T")[0],
          },
        });

        if (!eventRes.ok || !eventRes.data?.Event) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to create MISP event: ${eventRes.error || `HTTP ${eventRes.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const eventId = eventRes.data.Event.id;
        const safeEventId = safePathSegment(eventId, "eventId");

        // Add ATT&CK technique tags
        const addedTags: string[] = [];
        for (const tech of resolvedTechs) {
          const tagName = `misp-galaxy:mitre-attack-pattern="${tech.id} - ${tech.name}"`;
          const tagRes = await client.request("POST", `/events/addTag/${safeEventId}`, {
            tag: tagName,
          });
          if (tagRes.ok) addedTags.push(tagName);
        }

        // Add tactic tags
        const tactics = [...new Set(resolvedTechs.flatMap((t) => t.tactics))];
        for (const tactic of tactics) {
          const tagRes = await client.request("POST", `/events/addTag/${safeEventId}`, {
            tag: `mitre:tactic="${tactic}"`,
          });
          if (tagRes.ok) addedTags.push(`mitre:tactic="${tactic}"`);
        }

        // Add attributes
        const addedAttributes: string[] = [];
        if (attributes && attributes.length > 0) {
          for (const attr of attributes) {
            const attrRes = await client.request(
              "POST",
              `/attributes/add/${safeEventId}`,
              {
                type: attr.type,
                value: attr.value,
                category: attr.category || "Network activity",
                to_ids: attr.toIds ?? true,
                comment: attr.comment || "",
              },
            );
            if (attrRes.ok) {
              addedAttributes.push(`${attr.type}: ${attr.value}`);
            }
          }
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  eventId,
                  eventUuid: eventRes.data.Event.uuid,
                  info,
                  techniquesTagged: resolvedTechs.map((t) => t.id),
                  tacticsTagged: tactics,
                  tagsAdded: addedTags.length,
                  attributesAdded: addedAttributes,
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

  server.tool(
    "mitre_misp_list_events",
    "List recent MISP events with ATT&CK technique enrichment",
    {
      limit: z.number().optional().describe("Number of events (default: 10)"),
      searchTag: z.string().optional().describe("Filter by tag (e.g., technique ID)"),
    },
    async ({ limit, searchTag }) => {
      try {
        const searchBody: Record<string, unknown> = {
          returnFormat: "json",
          limit: limit || 10,
          page: 1,
        };

        if (searchTag) {
          const tech = store.getTechnique(searchTag);
          if (tech) {
            searchBody.tags = [
              `misp-galaxy:mitre-attack-pattern="${tech.id} - ${tech.name}"`,
            ];
          } else {
            searchBody.tags = [searchTag];
          }
        }

        const res = await client.request<{
          response?: Array<{
            Event: {
              id: string;
              info: string;
              date: string;
              threat_level_id: string;
              analysis: string;
              attribute_count: string;
              Tag?: Array<{ name: string }>;
            };
          }>;
        }>("POST", "/events/restSearch", searchBody);

        if (!res.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to list MISP events: ${res.error || `HTTP ${res.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const events = (res.data?.response || []).map((item) => {
          const event = item.Event;
          const attackTags = (event.Tag || [])
            .map((t) => t.name)
            .filter((n) => n.match(/T\d{4}/))
            .map((n) => {
              const match = n.match(/T\d{4}(?:\.\d{3})?/);
              return match ? match[0] : null;
            })
            .filter((t): t is string => t !== null);

          const techniqueDetails = attackTags
            .map((id) => {
              const tech = store.getTechnique(id);
              return tech ? { id: tech.id, name: tech.name } : null;
            })
            .filter((t): t is NonNullable<typeof t> => t !== null);

          const threatLevel = ["", "High", "Medium", "Low"][
            parseInt(event.threat_level_id) || 3
          ];

          return {
            eventId: event.id,
            info: event.info,
            date: event.date,
            threatLevel,
            attributeCount: parseInt(event.attribute_count),
            attackTechniques: techniqueDetails,
          };
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { count: events.length, events },
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
