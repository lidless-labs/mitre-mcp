import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { AttackDataStore } from "./data/index.js";
import { registerTechniqueTools } from "./tools/techniques.js";
import { registerTacticTools } from "./tools/tactics.js";
import { registerGroupTools } from "./tools/groups.js";
import { registerSoftwareTools } from "./tools/software.js";
import { registerMitigationTools } from "./tools/mitigations.js";
import { registerDataSourceTools } from "./tools/datasources.js";
import { registerMappingTools } from "./tools/mapping.js";
import { registerCampaignTools } from "./tools/campaigns.js";
import { registerNavigatorTools } from "./tools/navigator.js";
import { registerManagementTools } from "./tools/management.js";
import { registerResources } from "./resources.js";
import { registerPrompts } from "./prompts.js";
import {
  WazuhClient,
  TheHiveClient,
  CortexClient,
  MispClient,
  registerWazuhTools,
  registerTheHiveTools,
  registerCortexTools,
  registerMispTools,
  registerCorrelationTools,
} from "./soc/index.js";

async function main(): Promise<void> {
  const config = loadConfig();

  const server = new McpServer({
    name: "mitre-mcp",
    version: "2.0.0",
    description:
      "MITRE ATT&CK MCP server with SOC integration (Wazuh, TheHive, Cortex, MISP). Technique lookup, threat intelligence, detection coverage, alert mapping, campaign analysis, and cross-stack correlation.",
  });

  const store = new AttackDataStore(config);

  // Initialize data store (downloads on first run, uses cache after)
  console.error("Loading ATT&CK data...");
  try {
    await store.initialize();
    const stats = store.getStats();
    console.error(
      `ATT&CK data loaded: ${stats.techniques} techniques, ${stats.groups} groups, ${stats.software} software, ${stats.mitigations} mitigations, ${stats.campaigns} campaigns`,
    );
  } catch (error) {
    console.error(
      `Warning: Failed to load ATT&CK data: ${error instanceof Error ? error.message : String(error)}`,
    );
    console.error("Some tools may not work until data is available.");
  }

  // Register core ATT&CK tools
  registerTechniqueTools(server, store);
  registerTacticTools(server, store);
  registerGroupTools(server, store);
  registerSoftwareTools(server, store);
  registerMitigationTools(server, store);
  registerDataSourceTools(server, store);
  registerMappingTools(server, store);
  registerCampaignTools(server, store);
  registerNavigatorTools(server, store);
  registerManagementTools(server, store, config);

  // Register resources and prompts
  registerResources(server, store, config);
  registerPrompts(server);

  // Initialize SOC clients and register integration tools
  const socClients: {
    wazuh?: WazuhClient;
    thehive?: TheHiveClient;
    cortex?: CortexClient;
    misp?: MispClient;
  } = {};

  if (config.soc.wazuh) {
    console.error(`Wazuh integration enabled: ${config.soc.wazuh.url}`);
    const wazuhClient = new WazuhClient(config.soc.wazuh);
    socClients.wazuh = wazuhClient;
    registerWazuhTools(server, store, wazuhClient);
  }

  if (config.soc.thehive) {
    console.error(`TheHive integration enabled: ${config.soc.thehive.url}`);
    const thehiveClient = new TheHiveClient(config.soc.thehive);
    socClients.thehive = thehiveClient;
    registerTheHiveTools(server, store, thehiveClient);
  }

  if (config.soc.cortex) {
    console.error(`Cortex integration enabled: ${config.soc.cortex.url}`);
    const cortexClient = new CortexClient(config.soc.cortex);
    socClients.cortex = cortexClient;
    registerCortexTools(server, store, cortexClient);
  }

  if (config.soc.misp) {
    console.error(`MISP integration enabled: ${config.soc.misp.url}`);
    const mispClient = new MispClient(config.soc.misp);
    socClients.misp = mispClient;
    registerMispTools(server, store, mispClient);
  }

  // Register cross-stack correlation tools (always available, uses whatever clients exist)
  registerCorrelationTools(server, store, socClients);

  // Connect to transport
  const transport = new StdioServerTransport();
  // Strip the draft-07 `$schema` the MCP SDK stamps on tool schemas; Anthropic
  // rejects it ("must match JSON Schema draft 2020-12") when the full tool set
  // is sent, e.g. on subagent spawns. Intercept tools/list output here.
  const __send = transport.send.bind(transport);
  (transport as any).send = (message: any) => {
    const tools = message?.result?.tools;
    if (Array.isArray(tools)) {
      for (const t of tools) {
        if (t?.inputSchema) delete t.inputSchema.$schema;
        if (t?.outputSchema) delete t.outputSchema.$schema;
      }
    }
    return __send(message);
  };
  await server.connect(transport);

  const socList = Object.keys(socClients);
  console.error(
    `MITRE ATT&CK MCP server v2.0.0 running on stdio${socList.length > 0 ? ` | SOC: ${socList.join(", ")}` : ""}`,
  );
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
