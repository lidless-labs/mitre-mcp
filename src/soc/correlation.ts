import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";
import type { WazuhClient, TheHiveClient, MispClient } from "./client.js";

export function registerCorrelationTools(
  server: McpServer,
  store: AttackDataStore,
  clients: {
    wazuh?: WazuhClient;
    thehive?: TheHiveClient;
    misp?: MispClient;
  },
): void {
  server.tool(
    "mitre_soc_status",
    "Get connection status for all configured SOC integrations (Wazuh, TheHive, Cortex, MISP)",
    {},
    async () => {
      try {
        const status: Record<string, { connected: boolean; details?: unknown; error?: string }> = {};

        if (clients.wazuh) {
          const res = await clients.wazuh.request("GET", "/manager/info");
          status.wazuh = res.ok
            ? { connected: true, details: res.data }
            : { connected: false, error: res.error };
        } else {
          status.wazuh = { connected: false, error: "Not configured (set WAZUH_URL)" };
        }

        if (clients.thehive) {
          const res = await clients.thehive.request("GET", "/api/v1/user/current");
          status.thehive = res.ok
            ? { connected: true, details: { user: (res.data as Record<string, unknown>)?.login } }
            : { connected: false, error: res.error };
        } else {
          status.thehive = { connected: false, error: "Not configured (set THEHIVE_URL)" };
        }

        if (clients.misp) {
          const res = await clients.misp.request("GET", "/servers/getVersion");
          status.misp = res.ok
            ? { connected: true, details: res.data }
            : { connected: false, error: res.error };
        } else {
          status.misp = { connected: false, error: "Not configured (set MISP_URL)" };
        }

        const attackStats = store.getStats();

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  socIntegrations: status,
                  attackData: attackStats,
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
    "mitre_cross_correlate",
    "Cross-correlate ATT&CK techniques across Wazuh alerts, TheHive cases, and MISP events to find related activity",
    {
      techniques: z
        .array(z.string())
        .describe("ATT&CK technique IDs to search across all platforms"),
    },
    async ({ techniques }) => {
      try {
        const resolvedTechs = techniques
          .map((id) => store.getTechnique(id))
          .filter((t): t is NonNullable<typeof t> => !!t);

        if (resolvedTechs.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: "No valid techniques found",
              },
            ],
            isError: true,
          };
        }

        const results: Record<string, unknown> = {
          techniques: resolvedTechs.map((t) => ({
            id: t.id,
            name: t.name,
            tactics: t.tactics,
          })),
        };

        // Search Wazuh for alerts matching these techniques
        if (clients.wazuh) {
          try {
            // Wazuh API doesn't have a direct MITRE search, so we fetch recent alerts
            // and filter by MITRE ID in the response
            const alertsRes = await clients.wazuh.request<{
              data?: {
                affected_items?: Array<{
                  id: string;
                  timestamp: string;
                  rule: {
                    id: number;
                    description: string;
                    level: number;
                    mitre?: { id?: string[]; tactic?: string[] };
                  };
                  agent: { id: string; name: string };
                }>;
              };
            }>("GET", "/alerts?limit=100&sort=-timestamp");

            if (alertsRes.ok) {
              const techIds = new Set(resolvedTechs.map((t) => t.id));
              const matchingAlerts = (alertsRes.data?.data?.affected_items || [])
                .filter((alert) =>
                  (alert.rule.mitre?.id || []).some((id) => techIds.has(id)),
                )
                .slice(0, 20)
                .map((alert) => ({
                  alertId: alert.id,
                  timestamp: alert.timestamp,
                  ruleId: alert.rule.id,
                  description: alert.rule.description,
                  level: alert.rule.level,
                  agent: alert.agent.name,
                  matchedTechniques: (alert.rule.mitre?.id || []).filter((id) =>
                    techIds.has(id),
                  ),
                }));

              results.wazuhAlerts = {
                found: matchingAlerts.length,
                alerts: matchingAlerts,
              };
            }
          } catch {
            results.wazuhAlerts = { error: "Failed to query Wazuh" };
          }
        }

        // Search TheHive for cases tagged with these techniques
        if (clients.thehive) {
          try {
            const mitreTags = resolvedTechs.map((t) => `mitre:${t.id}`);
            const casesRes = await clients.thehive.request<
              Array<{
                _id: string;
                title: string;
                severity: number;
                status: string;
                tags: string[];
                _createdAt: number;
              }>
            >("POST", "/api/v1/query", {
              query: [
                { _name: "listCase" },
                { _name: "sort", _fields: [{ _field: "_createdAt", _order: "desc" }] },
                { _name: "page", from: 0, to: 50 },
              ],
            });

            if (casesRes.ok && Array.isArray(casesRes.data)) {
              const tagSet = new Set(mitreTags);
              const matchingCases = casesRes.data
                .filter((c) => c.tags.some((t) => tagSet.has(t)))
                .slice(0, 10)
                .map((c) => ({
                  caseId: c._id,
                  title: c.title,
                  severity: c.severity,
                  status: c.status,
                  createdAt: new Date(c._createdAt).toISOString(),
                  matchedTags: c.tags.filter((t) => tagSet.has(t)),
                }));

              results.thehiveCases = {
                found: matchingCases.length,
                cases: matchingCases,
              };
            }
          } catch {
            results.thehiveCases = { error: "Failed to query TheHive" };
          }
        }

        // Search MISP for events with these techniques
        if (clients.misp) {
          try {
            const mispTags = resolvedTechs.map(
              (t) => `misp-galaxy:mitre-attack-pattern="${t.id} - ${t.name}"`,
            );

            const eventsRes = await clients.misp.request<{
              response?: Array<{
                Event: {
                  id: string;
                  info: string;
                  date: string;
                  threat_level_id: string;
                  attribute_count: string;
                };
              }>;
            }>("POST", "/events/restSearch", {
              returnFormat: "json",
              tags: mispTags,
              limit: 10,
            });

            if (eventsRes.ok) {
              const matchingEvents = (eventsRes.data?.response || []).map((item) => ({
                eventId: item.Event.id,
                info: item.Event.info,
                date: item.Event.date,
                threatLevel: ["", "High", "Medium", "Low"][
                  parseInt(item.Event.threat_level_id) || 3
                ],
                attributeCount: parseInt(item.Event.attribute_count),
              }));

              results.mispEvents = {
                found: matchingEvents.length,
                events: matchingEvents,
              };
            }
          } catch {
            results.mispEvents = { error: "Failed to query MISP" };
          }
        }

        // ATT&CK enrichment
        const mitigations = resolvedTechs.flatMap((t) => {
          const mits = store.getMitigationsForTechnique(t.id);
          return mits.map((m) => ({
            forTechnique: t.id,
            id: m.mitigation.id,
            name: m.mitigation.name,
          }));
        });

        const groups = store
          .getAllGroups()
          .map((group) => {
            const groupTechs = store
              .getGroupTechniques(group.stixId)
              .map((t) => t.technique.id);
            const techIds = new Set(resolvedTechs.map((t) => t.id));
            const shared = groupTechs.filter((t) => techIds.has(t));
            return {
              id: group.id,
              name: group.name,
              overlapCount: shared.length,
              sharedTechniques: shared,
            };
          })
          .filter((m) => m.overlapCount > 0)
          .sort((a, b) => b.overlapCount - a.overlapCount)
          .slice(0, 5);

        results.attackEnrichment = {
          mitigations,
          likelyThreatGroups: groups,
        };

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(results, null, 2),
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
