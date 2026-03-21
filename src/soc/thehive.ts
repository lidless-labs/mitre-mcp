import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";
import type { TheHiveClient } from "./client.js";

export function registerTheHiveTools(
  server: McpServer,
  store: AttackDataStore,
  client: TheHiveClient,
): void {
  server.tool(
    "mitre_thehive_enrich",
    "Enrich TheHive case observables with ATT&CK context. Takes a case ID and adds ATT&CK technique tags, suggested mitigations, and threat group correlations.",
    {
      caseId: z.string().describe("TheHive case ID"),
      addTags: z
        .boolean()
        .optional()
        .describe("Add ATT&CK technique tags to the case (default: false, read-only analysis)"),
    },
    async ({ caseId, addTags }) => {
      try {
        // Get case details
        const caseRes = await client.request<{
          _id: string;
          title: string;
          description: string;
          tags: string[];
          severity: number;
          status: string;
        }>("GET", `/api/v1/case/${caseId}`);

        if (!caseRes.ok || !caseRes.data) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to fetch case ${caseId}: ${caseRes.error || `HTTP ${caseRes.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const theCase = caseRes.data;

        // Get observables for the case
        const obsRes = await client.request<Array<{
          _id: string;
          dataType: string;
          data?: string;
          message?: string;
          tags: string[];
          ioc: boolean;
        }>>("POST", "/api/v1/query", {
          query: [
            { _name: "getCase", idOrName: caseId },
            { _name: "observables" },
          ],
        });

        const observables = Array.isArray(obsRes.data) ? obsRes.data : [];

        // Extract indicators for technique mapping
        const indicators: string[] = [];
        const observableTypes: string[] = [];

        for (const obs of observables) {
          if (obs.data) indicators.push(obs.data);
          if (obs.message) indicators.push(obs.message);
          observableTypes.push(obs.dataType);
        }

        // Map case description + observable data to techniques
        const searchText = [
          theCase.title,
          theCase.description,
          ...indicators,
        ].join(" ");

        const keywords = searchText
          .toLowerCase()
          .split(/[\s,;:!?()[\]{}'"\/\\|@#$%^&*+=<>~`]+/)
          .filter((w) => w.length > 2)
          .filter(
            (w) =>
              ![
                "the", "and", "for", "was", "with", "from", "that", "this",
                "are", "has", "have", "not", "but", "can", "case", "alert",
              ].includes(w),
          );

        const allTechniques = store.getAllTechniques();
        const scored = allTechniques
          .map((t) => {
            let score = 0;
            const reasons: string[] = [];

            for (const kw of keywords) {
              if (t.name.toLowerCase().includes(kw)) {
                score += 3;
                reasons.push(`Name matches "${kw}"`);
              }
              if (t.detection.toLowerCase().includes(kw)) {
                score += 2;
                reasons.push(`Detection mentions "${kw}"`);
              }
              if (t.description.toLowerCase().includes(kw)) {
                score += 1;
              }
            }

            return { technique: t, score, reasons };
          })
          .filter((r) => r.score > 2)
          .sort((a, b) => b.score - a.score)
          .slice(0, 15);

        const maxScore = scored[0]?.score || 1;
        const techniqueMatches = scored.map((r) => ({
          id: r.technique.id,
          name: r.technique.name,
          tactics: r.technique.tactics,
          confidence: Math.min(Math.round((r.score / maxScore) * 100), 100),
          reasons: [...new Set(r.reasons)].slice(0, 5),
        }));

        // Extract existing ATT&CK tags
        const existingAttackTags = theCase.tags.filter(
          (t) => t.match(/^T\d{4}/) || t.startsWith("mitre:") || t.startsWith("attack."),
        );

        // Get mitigations for top matches
        const mitigations = techniqueMatches
          .slice(0, 5)
          .flatMap((m) => {
            const mits = store.getMitigationsForTechnique(m.id);
            return mits.map((mit) => ({
              forTechnique: m.id,
              id: mit.mitigation.id,
              name: mit.mitigation.name,
            }));
          });

        // Find likely threat groups
        const matchedIds = new Set(techniqueMatches.map((m) => m.id));
        const groupMatches = store
          .getAllGroups()
          .map((group) => {
            const groupTechs = store
              .getGroupTechniques(group.stixId)
              .map((t) => t.technique.id);
            const shared = groupTechs.filter((t) => matchedIds.has(t));
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

        // Optionally add tags to the case
        let tagsAdded: string[] = [];
        if (addTags && techniqueMatches.length > 0) {
          const newTags = techniqueMatches
            .slice(0, 10)
            .map((m) => `mitre:${m.id}`)
            .filter((t) => !theCase.tags.includes(t));

          if (newTags.length > 0) {
            const updateRes = await client.request("PATCH", `/api/v1/case/${caseId}`, {
              tags: [...theCase.tags, ...newTags],
            });

            if (updateRes.ok) {
              tagsAdded = newTags;
            }
          }
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  caseId: theCase._id,
                  caseTitle: theCase.title,
                  caseSeverity: theCase.severity,
                  caseStatus: theCase.status,
                  observableCount: observables.length,
                  observableTypes: [...new Set(observableTypes)],
                  existingAttackTags,
                  techniqueMatches,
                  suggestedMitigations: mitigations,
                  likelyThreatGroups: groupMatches,
                  tagsAdded,
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
    "mitre_thehive_create_case",
    "Create a new TheHive case pre-populated with ATT&CK context from observed techniques",
    {
      title: z.string().describe("Case title"),
      description: z.string().optional().describe("Case description"),
      techniques: z
        .array(z.string())
        .describe("Observed ATT&CK technique IDs"),
      severity: z
        .number()
        .optional()
        .describe("Case severity (1=low, 2=medium, 3=high, 4=critical)"),
      tlp: z
        .number()
        .optional()
        .describe("TLP level (0=white, 1=green, 2=amber, 3=red)"),
      observables: z
        .array(
          z.object({
            dataType: z.string().describe("Observable type (ip, domain, hash, filename, url, mail, etc.)"),
            data: z.string().describe("Observable value"),
            ioc: z.boolean().optional().describe("Mark as IOC"),
            message: z.string().optional().describe("Observable description"),
          }),
        )
        .optional()
        .describe("Observables to add to the case"),
    },
    async ({ title, description, techniques, severity, tlp, observables }) => {
      try {
        // Resolve techniques
        const resolvedTechs = techniques
          .map((id) => store.getTechnique(id))
          .filter((t): t is NonNullable<typeof t> => !!t);

        if (resolvedTechs.length === 0) {
          return {
            content: [
              {
                type: "text" as const,
                text: "No valid ATT&CK techniques found from provided IDs",
              },
            ],
            isError: true,
          };
        }

        // Build description with ATT&CK context
        const attackContext = resolvedTechs
          .map((t) => `- **${t.id}** ${t.name} (${t.tactics.join(", ")})`)
          .join("\n");

        const mitigationContext = resolvedTechs
          .flatMap((t) => {
            const mits = store.getMitigationsForTechnique(t.id);
            return mits.map(
              (m) => `- ${m.mitigation.id} ${m.mitigation.name} (for ${t.id})`,
            );
          })
          .slice(0, 10)
          .join("\n");

        const fullDescription = [
          description || "",
          "",
          "## ATT&CK Techniques",
          attackContext,
          "",
          "## Recommended Mitigations",
          mitigationContext || "No specific mitigations found.",
        ].join("\n");

        // Tags
        const tags = [
          ...resolvedTechs.map((t) => `mitre:${t.id}`),
          ...new Set(resolvedTechs.flatMap((t) => t.tactics.map((ta) => `attack.${ta}`))),
        ];

        // Create the case
        const caseRes = await client.request<{ _id: string }>(
          "POST",
          "/api/v1/case",
          {
            title,
            description: fullDescription,
            severity: severity || 2,
            tlp: tlp || 2,
            tags,
            flag: false,
          },
        );

        if (!caseRes.ok || !caseRes.data) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to create case: ${caseRes.error || `HTTP ${caseRes.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const caseId = caseRes.data._id;

        // Add observables if provided
        const addedObservables: string[] = [];
        if (observables && observables.length > 0) {
          for (const obs of observables) {
            const obsRes = await client.request(
              "POST",
              `/api/v1/case/${caseId}/observable`,
              {
                dataType: obs.dataType,
                data: obs.data,
                ioc: obs.ioc || false,
                message: obs.message || "",
                tags: [],
              },
            );
            if (obsRes.ok) {
              addedObservables.push(`${obs.dataType}: ${obs.data}`);
            }
          }
        }

        // Create tasks for each tactic phase
        const tacticPhases = [...new Set(resolvedTechs.flatMap((t) => t.tactics))];
        const createdTasks: string[] = [];

        for (const tactic of tacticPhases) {
          const relevantTechs = resolvedTechs
            .filter((t) => t.tactics.includes(tactic))
            .map((t) => `${t.id} ${t.name}`)
            .join(", ");

          const taskRes = await client.request(
            "POST",
            `/api/v1/case/${caseId}/task`,
            {
              title: `Investigate: ${tactic}`,
              description: `Investigate techniques in the ${tactic} phase: ${relevantTechs}`,
              status: "Waiting",
              flag: false,
            },
          );

          if (taskRes.ok) {
            createdTasks.push(`Investigate: ${tactic}`);
          }
        }

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  caseId,
                  title,
                  techniquesLinked: resolvedTechs.map((t) => t.id),
                  tags,
                  observablesAdded: addedObservables,
                  tasksCreated: createdTasks,
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
    "mitre_thehive_list_cases",
    "List TheHive cases with optional ATT&CK technique filtering",
    {
      limit: z.number().optional().describe("Number of cases to return (default: 10)"),
      techniqueFilter: z
        .string()
        .optional()
        .describe("Filter cases by ATT&CK technique ID tag"),
      status: z
        .enum(["New", "InProgress", "Resolved", "Closed"])
        .optional()
        .describe("Filter by case status"),
    },
    async ({ limit, techniqueFilter, status }) => {
      try {
        const query: unknown[] = [{ _name: "listCase" }];

        if (status) {
          query.push({ _name: "filter", _field: "status", _value: status });
        }

        query.push({ _name: "sort", _fields: [{ _field: "_createdAt", _order: "desc" }] });
        query.push({ _name: "page", from: 0, to: limit || 10 });

        const res = await client.request<
          Array<{
            _id: string;
            title: string;
            severity: number;
            status: string;
            tags: string[];
            _createdAt: number;
          }>
        >("POST", "/api/v1/query", { query });

        if (!res.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to list cases: ${res.error || `HTTP ${res.status}`}`,
              },
            ],
            isError: true,
          };
        }

        let cases = Array.isArray(res.data) ? res.data : [];

        // Filter by technique tag if specified
        if (techniqueFilter) {
          const tag = techniqueFilter.startsWith("mitre:")
            ? techniqueFilter
            : `mitre:${techniqueFilter}`;
          cases = cases.filter((c) => c.tags.includes(tag));
        }

        // Enrich with ATT&CK context
        const enriched = cases.map((c) => {
          const mitreTags = c.tags
            .filter((t) => t.startsWith("mitre:"))
            .map((t) => t.replace("mitre:", ""));

          const techniqueDetails = mitreTags
            .map((id) => {
              const tech = store.getTechnique(id);
              return tech ? { id: tech.id, name: tech.name, tactics: tech.tactics } : null;
            })
            .filter((t): t is NonNullable<typeof t> => t !== null);

          return {
            caseId: c._id,
            title: c.title,
            severity: c.severity,
            status: c.status,
            createdAt: new Date(c._createdAt).toISOString(),
            attackTechniques: techniqueDetails,
            allTags: c.tags,
          };
        });

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                { count: enriched.length, cases: enriched },
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
