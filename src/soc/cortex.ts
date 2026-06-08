import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { AttackDataStore } from "../data/index.js";
import type { CortexClient } from "./client.js";
import { safePathSegment, writesAllowed } from "./util.js";

// Mapping of common Cortex analyzer types to ATT&CK data sources
const ANALYZER_TO_DATASOURCE: Record<string, string[]> = {
  FileInfo: ["File"],
  Yara: ["File"],
  VirusTotal: ["File", "Network Traffic"],
  AbuseIPDB: ["Network Traffic"],
  MaxMind: ["Network Traffic"],
  Shodan: ["Network Traffic"],
  DomainMailSPFDMARC: ["Network Traffic"],
  DNSDB: ["Network Traffic"],
  URLhaus: ["Network Traffic"],
  OTXQuery: ["Network Traffic", "File"],
  MISP: ["Network Traffic", "File"],
  Cortex_Responder: ["Process", "Command"],
  HybridAnalysis: ["File", "Process"],
  JoeSandbox: ["File", "Process"],
  CuckooSandbox: ["File", "Process", "Network Traffic"],
  PassiveTotal: ["Network Traffic"],
  ThreatCrowd: ["Network Traffic"],
};

export function registerCortexTools(
  server: McpServer,
  store: AttackDataStore,
  client: CortexClient,
): void {
  server.tool(
    "mitre_cortex_analyzer_coverage",
    "Map Cortex analyzers to ATT&CK data sources and calculate technique detection potential",
    {},
    async () => {
      try {
        // Get list of available analyzers
        const analyzersRes = await client.request<
          Array<{
            id: string;
            name: string;
            version: string;
            dataTypeList: string[];
            description?: string;
          }>
        >("GET", "/api/analyzer");

        if (!analyzersRes.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to fetch Cortex analyzers: ${analyzersRes.error || `HTTP ${analyzersRes.status}`}`,
              },
            ],
            isError: true,
          };
        }

        const analyzers = Array.isArray(analyzersRes.data) ? analyzersRes.data : [];

        // Map analyzers to data sources
        const coveredDataSources = new Set<string>();
        const analyzerMappings = analyzers.map((analyzer) => {
          const dataSources: string[] = [];

          // Match by analyzer name prefix
          for (const [prefix, ds] of Object.entries(ANALYZER_TO_DATASOURCE)) {
            if (analyzer.name.toLowerCase().includes(prefix.toLowerCase())) {
              dataSources.push(...ds);
              for (const d of ds) coveredDataSources.add(d);
            }
          }

          // Infer from data types
          for (const dt of analyzer.dataTypeList || []) {
            switch (dt) {
              case "file":
              case "hash":
                if (!dataSources.includes("File")) {
                  dataSources.push("File");
                  coveredDataSources.add("File");
                }
                break;
              case "ip":
              case "domain":
              case "url":
              case "fqdn":
                if (!dataSources.includes("Network Traffic")) {
                  dataSources.push("Network Traffic");
                  coveredDataSources.add("Network Traffic");
                }
                break;
              case "mail":
                if (!dataSources.includes("Network Traffic")) {
                  dataSources.push("Network Traffic");
                  coveredDataSources.add("Network Traffic");
                }
                break;
            }
          }

          return {
            name: analyzer.name,
            version: analyzer.version,
            dataTypes: analyzer.dataTypeList,
            mappedDataSources: [...new Set(dataSources)],
          };
        });

        // Calculate technique coverage through data sources
        const allDataSources = store.getAllDataSources();
        const allComponents = store.getDataComponents();

        const availableDsStixIds = new Set(
          allDataSources
            .filter((ds) => coveredDataSources.has(ds.name))
            .map((ds) => ds.stixId),
        );

        const availableComponentIds = new Set(
          allComponents
            .filter((dc) => availableDsStixIds.has(dc.dataSourceId))
            .map((dc) => dc.stixId),
        );

        const detectableTechIds = new Set<string>();
        for (const rel of store.getRelationships()) {
          if (
            rel.relationshipType === "detects" &&
            availableComponentIds.has(rel.sourceRef)
          ) {
            const tech = store.getTechniqueByStixId(rel.targetRef);
            if (tech) detectableTechIds.add(tech.id);
          }
        }

        const allTechniques = store.getAllTechniques().filter((t) => !t.isSubtechnique);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  analyzerCount: analyzers.length,
                  analyzers: analyzerMappings,
                  coveredDataSources: [...coveredDataSources],
                  techniqueDetectionPotential: {
                    detectableTechniques: detectableTechIds.size,
                    totalTechniques: allTechniques.length,
                    coveragePercentage: Math.round(
                      (detectableTechIds.size / allTechniques.length) * 100,
                    ),
                  },
                  uncoveredDataSources: allDataSources
                    .filter((ds) => !coveredDataSources.has(ds.name))
                    .map((ds) => ds.name)
                    .slice(0, 10),
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
    "mitre_cortex_run_analyzers",
    "Run Cortex analyzers on an observable and map results to ATT&CK context",
    {
      data: z.string().describe("Observable value (IP, domain, hash, filename, URL)"),
      dataType: z
        .enum(["ip", "domain", "url", "fqdn", "hash", "file", "filename", "mail"])
        .describe("Observable data type"),
      analyzers: z
        .array(z.string())
        .optional()
        .describe("Specific analyzer names to run (runs all compatible if omitted)"),
      tlp: z
        .number()
        .optional()
        .describe("TLP level (0=white, 1=green, 2=amber, 3=red, default: 2)"),
      confirm: z
        .boolean()
        .optional()
        .describe(
          "Must be true to actually submit live analyzer jobs to Cortex against the observable. Defaults to false (dry-run: returns the analyzers that would run without submitting). Can also be globally enabled via MITRE_SOC_ALLOW_WRITES.",
        ),
    },
    async ({ data, dataType, analyzers, tlp, confirm }) => {
      try {
        // dataType is schema-constrained, but encode defensively before it
        // enters the request path.
        const safeDataType = safePathSegment(dataType, "dataType");
        // Get available analyzers for this data type
        const analyzersRes = await client.request<
          Array<{ id: string; name: string; dataTypeList: string[] }>
        >("GET", `/api/analyzer/type/${safeDataType}`);

        if (!analyzersRes.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Failed to fetch analyzers for type ${dataType}: ${analyzersRes.error || `HTTP ${analyzersRes.status}`}`,
              },
            ],
            isError: true,
          };
        }

        let availableAnalyzers = Array.isArray(analyzersRes.data) ? analyzersRes.data : [];

        if (analyzers && analyzers.length > 0) {
          const filterSet = new Set(analyzers.map((a) => a.toLowerCase()));
          availableAnalyzers = availableAnalyzers.filter((a) =>
            filterSet.has(a.name.toLowerCase()),
          );
        }

        const analyzersToRun = availableAnalyzers.slice(0, 5);

        // Write guard: submitting live analyzer jobs runs active tooling
        // against an attacker-influenced observable (sandboxes detonate files,
        // reputation lookups leak IOCs). Require explicit confirmation.
        if (!writesAllowed(confirm)) {
          const dryRunHints: Record<string, string[]> = {
            ip: ["T1071", "T1573", "T1041", "T1090"],
            domain: ["T1071", "T1568", "T1583.001"],
            url: ["T1071.001", "T1566.002", "T1189"],
            hash: ["T1204", "T1059"],
            file: ["T1204", "T1059", "T1027"],
            mail: ["T1566.001", "T1566.002"],
          };
          const suggestedTechniques = (dryRunHints[dataType] || [])
            .map((id) => {
              const tech = store.getTechnique(id);
              return tech ? { id: tech.id, name: tech.name } : null;
            })
            .filter((t): t is NonNullable<typeof t> => t !== null);

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify(
                  {
                    dryRun: true,
                    message:
                      "Dry run: no analyzer jobs submitted. Set confirm=true (or MITRE_SOC_ALLOW_WRITES=true) to run.",
                    observable: { data, dataType },
                    analyzersThatWouldRun: analyzersToRun.map((a) => a.name),
                    suggestedAttackContext: suggestedTechniques,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // Run analyzers (submit jobs)
        const jobs: Array<{ analyzerId: string; analyzerName: string; jobId?: string; error?: string }> = [];

        for (const analyzer of analyzersToRun) {
          const jobRes = await client.request<{ id: string }>(
            "POST",
            `/api/analyzer/${safePathSegment(analyzer.id, "analyzerId")}/run`,
            {
              data,
              dataType,
              tlp: tlp ?? 2,
              message: "MITRE MCP analysis",
            },
          );

          if (jobRes.ok && jobRes.data) {
            jobs.push({
              analyzerId: analyzer.id,
              analyzerName: analyzer.name,
              jobId: jobRes.data.id,
            });
          } else {
            jobs.push({
              analyzerId: analyzer.id,
              analyzerName: analyzer.name,
              error: jobRes.error || `HTTP ${jobRes.status}`,
            });
          }
        }

        // Map the observable type to likely ATT&CK context
        const contextHints: Record<string, string[]> = {
          ip: ["T1071", "T1573", "T1041", "T1090"],
          domain: ["T1071", "T1568", "T1583.001"],
          url: ["T1071.001", "T1566.002", "T1189"],
          hash: ["T1204", "T1059"],
          file: ["T1204", "T1059", "T1027"],
          mail: ["T1566.001", "T1566.002"],
        };

        const suggestedTechniques = (contextHints[dataType] || [])
          .map((id) => {
            const tech = store.getTechnique(id);
            return tech ? { id: tech.id, name: tech.name, tactics: tech.tactics } : null;
          })
          .filter((t): t is NonNullable<typeof t> => t !== null);

        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(
                {
                  observable: { data, dataType },
                  analyzersRun: jobs.filter((j) => j.jobId).length,
                  analyzersFailed: jobs.filter((j) => j.error).length,
                  jobs,
                  suggestedAttackContext: suggestedTechniques,
                  note: "Jobs are asynchronous. Use Cortex API or TheHive to check results.",
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
