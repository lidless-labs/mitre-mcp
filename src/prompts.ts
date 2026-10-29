import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { externalDataJson } from "./soc/util.js";

export function registerPrompts(server: McpServer): void {
  server.prompt(
    "map-incident-to-attack",
    "Map an incident's observables to ATT&CK techniques, identify tactics, and suggest mitigations",
    {
      incidentDescription: z
        .string()
        .describe("Description of the security incident"),
      observables: z
        .string()
        .optional()
        .describe(
          "Comma-separated list of observables (IPs, domains, hashes, process names)",
        ),
    },
    async ({ incidentDescription, observables }) => {
      const prompt = `You are a threat intelligence analyst mapping a security incident to the MITRE ATT&CK framework.

${externalDataJson({ incidentDescription, observables }, "Caller-supplied incident data")}

Follow these steps:
1. Use mitre_map_alert_to_technique to identify likely ATT&CK techniques from the incident description and observables
2. For each identified technique, use mitre_get_technique to get full details
3. Map each technique to its tactics to understand the adversary's progression through the kill chain
4. Use mitre_mitigations_for_technique for each high-confidence technique to identify defensive measures
5. Use mitre_search_groups with the top techniques to identify potential threat actors
6. Compile a structured report with:
   - Identified techniques with confidence levels
   - Tactic coverage (which kill chain phases are represented)
   - Recommended mitigations prioritized by impact
   - Potential threat actor attribution (if patterns match known groups)
   - Detection gaps and recommended data sources to improve visibility`;

      return {
        messages: [
          {
            role: "user" as const,
            content: { type: "text" as const, text: prompt },
          },
        ],
      };
    },
  );

  server.prompt(
    "threat-hunt-plan",
    "Generate a threat hunting plan based on ATT&CK framework and available data sources",
    {
      focus: z
        .string()
        .optional()
        .describe(
          "Specific focus area (e.g., ransomware, APT, insider threat, lateral movement)",
        ),
      dataSources: z
        .string()
        .optional()
        .describe("Comma-separated list of available data sources"),
    },
    async ({ focus, dataSources }) => {
      const prompt = `You are a threat hunter building a hunt plan using the MITRE ATT&CK framework.

${externalDataJson({ focus, dataSources }, "Caller-supplied hunt data")}

Follow these steps:
1. ${dataSources ? "Use mitre_detection_coverage to assess current coverage with the available data sources above" : "Use mitre_list_tactics to understand the full kill chain"}
2. Identify high-priority techniques based on the hunt focus
3. For each priority technique, use mitre_get_technique to understand detection methods
4. Use mitre_search_groups to identify relevant threat actors for the focus area
5. Generate hunt hypotheses that map to specific techniques
6. For each hypothesis, specify:
   - ATT&CK technique reference
   - Data source and query logic
   - Expected indicators of compromise
   - False positive considerations
   - Escalation criteria`;

      return {
        messages: [
          {
            role: "user" as const,
            content: { type: "text" as const, text: prompt },
          },
        ],
      };
    },
  );

  server.prompt(
    "gap-analysis",
    "Perform a detection gap analysis using ATT&CK coverage mapping",
    {
      dataSources: z
        .string()
        .describe("Comma-separated list of data sources you currently collect"),
      priorityGroups: z
        .string()
        .optional()
        .describe(
          "Comma-separated list of priority threat groups to focus on",
        ),
    },
    async ({ dataSources, priorityGroups }) => {
      const prompt = `You are a detection engineer performing a gap analysis using the MITRE ATT&CK framework.

${externalDataJson({ dataSources, priorityGroups }, "Caller-supplied coverage data")}

Follow these steps:
1. Use mitre_detection_coverage with your available data sources to calculate coverage
2. Review the gaps by tactic to identify blind spots
${priorityGroups ? `3. For each priority group, use mitre_get_group to understand their techniques
4. Cross-reference group techniques with your detection gaps` : "3. Review the top gap recommendations"}
5. Use mitre_get_datasource for recommended data sources to understand implementation requirements
6. Compile a report with:
   - Current coverage percentage and breakdown by tactic
   - Critical gaps (techniques used by priority groups that you cannot detect)
   - Data source investment recommendations ranked by coverage impact
   - Quick wins (data sources that would cover the most gaps)
   - Long-term roadmap for improving coverage`;

      return {
        messages: [
          {
            role: "user" as const,
            content: { type: "text" as const, text: prompt },
          },
        ],
      };
    },
  );

  server.prompt(
    "attribution-analysis",
    "Assist with threat attribution based on observed techniques and contextual factors",
    {
      techniques: z
        .string()
        .describe("Comma-separated list of observed technique IDs"),
      targetSector: z
        .string()
        .optional()
        .describe("Target sector (e.g., government, finance, healthcare)"),
      targetRegion: z
        .string()
        .optional()
        .describe("Target region (e.g., North America, Europe, Asia)"),
    },
    async ({ techniques, targetSector, targetRegion }) => {
      const techList = techniques.split(",").map((t) => t.trim());
      const prompt = `You are a threat intelligence analyst performing attribution analysis using the MITRE ATT&CK framework.

${externalDataJson({ techniques: techList, targetSector, targetRegion }, "Caller-supplied attribution data")}

Follow these steps:
1. Use mitre_campaign_profile with the observed techniques to build a campaign profile
2. For each likely group identified, use mitre_get_group to get full details
3. Use mitre_technique_overlap with the techniques to find groups with highest overlap
4. For each candidate group, assess:
   - Technique overlap percentage
   - Historical targeting patterns (sectors, regions)
   - Typical software/tooling used
   - Known operational patterns
5. Compile an attribution assessment with:
   - Ranked list of candidate threat actors with confidence levels
   - Supporting evidence for each candidate
   - Technique gaps (observed techniques not associated with any known group)
   - Recommended next steps for improving attribution confidence
   - Caveats and limitations of the analysis`;

      return {
        messages: [
          {
            role: "user" as const,
            content: { type: "text" as const, text: prompt },
          },
        ],
      };
    },
  );
}
