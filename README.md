# MITRE ATT&CK MCP Server

[![TypeScript 5.7](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)
[![Node.js 20+](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org/)
[![MCP 1.x](https://img.shields.io/badge/MCP-1.x-purple)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

An MCP server providing comprehensive access to the MITRE ATT&CK knowledge base with full SOC stack integration. Enables LLMs to look up techniques, map alerts to ATT&CK, analyze detection coverage, profile campaigns, generate Navigator layers, and correlate across Wazuh, TheHive, Cortex, and MISP.

## Features

- **39 tools** for technique lookup, tactic navigation, group intelligence, software analysis, mitigation mapping, detection coverage, alert mapping, campaign profiling, Navigator layer export, and SOC integration
- **3 resources** for matrix overview, version info, and tactic listing
- **4 prompts** for incident mapping, threat hunting, gap analysis, and attribution
- **SOC Integration**: Wazuh alert mapping, TheHive case management, Cortex analyzer correlation, MISP event/IOC management
- **Cross-stack correlation**: Search for ATT&CK techniques across all connected platforms simultaneously
- **ATT&CK Navigator**: Generate layer JSON for heatmaps, group overlays, coverage maps, and diff views
- **Campaign support**: Full STIX campaign object parsing and attribution
- **Offline-capable** with local STIX 2.1 data caching
- **Auto-updating** with configurable refresh intervals
- **Enterprise, Mobile, and ICS** matrix support

## Prerequisites

- Node.js 20 or later
- Internet access for initial ATT&CK data download (cached locally after first run)
- (Optional) Wazuh, TheHive, Cortex, and/or MISP instances for SOC integration

## Installation

```bash
git clone https://github.com/solomonneas/mitre-mcp.git
cd mitre-mcp
npm install
npm run build
```

## Configuration

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_DATA_DIR` | `~/.mitre-mcp/data` | Local cache directory for STIX bundles |
| `MITRE_MATRICES` | `enterprise` | Comma-separated matrices: `enterprise`, `mobile`, `ics` |
| `MITRE_UPDATE_INTERVAL` | `86400` | Auto-update check interval in seconds (default 24h) |

### SOC Integration (all optional)

| Variable | Description |
|----------|-------------|
| `WAZUH_URL` | Wazuh API URL (e.g., `https://192.168.1.10:55000`) |
| `WAZUH_USERNAME` | Wazuh API username (default: `wazuh-wui`) |
| `WAZUH_PASSWORD` | Wazuh API password |
| `WAZUH_VERIFY_SSL` | Verify SSL certs (default: `true`, set `false` for self-signed) |
| `THEHIVE_URL` | TheHive URL (e.g., `http://192.168.1.11:9000`) |
| `THEHIVE_API_KEY` | TheHive API key |
| `CORTEX_URL` | Cortex URL (e.g., `http://192.168.1.11:9001`) |
| `CORTEX_API_KEY` | Cortex API key |
| `MISP_URL` | MISP URL (e.g., `https://192.168.1.12`) |
| `MISP_API_KEY` | MISP API key (authkey) |
| `MISP_VERIFY_SSL` | Verify SSL certs (default: `true`, set `false` for self-signed) |

## Usage

### Claude Desktop

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "node",
      "args": ["/path/to/mitre-mcp/dist/index.js"],
      "env": {
        "MITRE_MATRICES": "enterprise",
        "WAZUH_URL": "https://192.168.1.10:55000",
        "WAZUH_USERNAME": "wazuh-wui",
        "WAZUH_PASSWORD": "your-password",
        "WAZUH_VERIFY_SSL": "false",
        "THEHIVE_URL": "http://192.168.1.11:9000",
        "THEHIVE_API_KEY": "your-api-key",
        "CORTEX_URL": "http://192.168.1.11:9001",
        "CORTEX_API_KEY": "your-api-key",
        "MISP_URL": "https://192.168.1.12",
        "MISP_API_KEY": "your-api-key",
        "MISP_VERIFY_SSL": "false"
      }
    }
  }
}
```

### OpenClaw

Add to your `openclaw.json`:

```json
{
  "mcp": {
    "servers": {
      "mitre-attack": {
        "type": "stdio",
        "command": "node",
        "args": ["/path/to/mitre-mcp/dist/index.js"]
      }
    }
  }
}
```

### Standalone

```bash
npm run start
```

### Development

```bash
npm run dev
```

## Tool Reference

### Core ATT&CK Tools (19)

#### Technique Lookup

| Tool | Description |
|------|-------------|
| `mitre_get_technique` | Get full details of a technique by ID (T1059, T1059.001) |
| `mitre_search_techniques` | Search techniques by keyword, tactic, platform, data source |

#### Tactic Navigation

| Tool | Description |
|------|-------------|
| `mitre_list_tactics` | List all tactics in kill-chain order |
| `mitre_get_tactic` | Get tactic details with all associated techniques |

#### Threat Group Intelligence

| Tool | Description |
|------|-------------|
| `mitre_get_group` | Get group details including techniques and software used |
| `mitre_search_groups` | Search groups by keyword or technique usage |
| `mitre_list_groups` | List all known threat groups |

#### Software & Malware

| Tool | Description |
|------|-------------|
| `mitre_get_software` | Get software details with techniques and associated groups |
| `mitre_search_software` | Search software by name, technique, or type (malware/tool) |

#### Mitigation Mapping

| Tool | Description |
|------|-------------|
| `mitre_get_mitigation` | Get mitigation details with addressed techniques |
| `mitre_mitigations_for_technique` | Get all mitigations for a specific technique |
| `mitre_search_mitigations` | Search mitigations by keyword |

#### Detection & Data Sources

| Tool | Description |
|------|-------------|
| `mitre_get_datasource` | Get data source details with detectable techniques |
| `mitre_detection_coverage` | Analyze detection coverage based on available data sources |

#### Mapping & Correlation

| Tool | Description |
|------|-------------|
| `mitre_map_alert_to_technique` | Map security alerts to likely ATT&CK techniques |
| `mitre_technique_overlap` | Find technique overlap between groups for attribution |
| `mitre_attack_path` | Generate possible attack paths through the kill chain |

#### Data Management

| Tool | Description |
|------|-------------|
| `mitre_update_data` | Force update of the local ATT&CK data cache |
| `mitre_data_version` | Get current data version and object counts |

### Campaign Tools (4)

| Tool | Description |
|------|-------------|
| `mitre_campaign_profile` | Build a technique profile with group/software/campaign matching |
| `mitre_get_campaign` | Get campaign details with techniques, software, and groups |
| `mitre_list_campaigns` | List all known ATT&CK campaigns |
| `mitre_search_campaigns` | Search campaigns by keyword or technique |

### Navigator Layer Export (1)

| Tool | Description |
|------|-------------|
| `mitre_navigator_layer` | Generate ATT&CK Navigator JSON layers (coverage, group, campaign, diff) |

### Wazuh Integration (4)

| Tool | Description |
|------|-------------|
| `mitre_wazuh_status` | Wazuh manager status, agents, and rule stats |
| `mitre_map_wazuh_alert` | Map Wazuh alerts to ATT&CK techniques by rule ID/description/groups |
| `mitre_wazuh_rule_coverage` | Analyze Wazuh rules mapped to ATT&CK techniques |
| `mitre_wazuh_alerts` | Fetch recent alerts enriched with ATT&CK context |

### TheHive Integration (3)

| Tool | Description |
|------|-------------|
| `mitre_thehive_enrich` | Enrich a TheHive case with ATT&CK techniques and mitigations |
| `mitre_thehive_create_case` | Create a case pre-populated with ATT&CK context |
| `mitre_thehive_list_cases` | List cases with ATT&CK technique filtering |

### Cortex Integration (2)

| Tool | Description |
|------|-------------|
| `mitre_cortex_analyzer_coverage` | Map Cortex analyzers to ATT&CK data sources |
| `mitre_cortex_run_analyzers` | Run analyzers on observables with ATT&CK context |

### MISP Integration (4)

| Tool | Description |
|------|-------------|
| `mitre_misp_event_to_attack` | Map MISP event attributes/galaxies to ATT&CK |
| `mitre_misp_search_indicators` | Search MISP IOCs by technique or group |
| `mitre_misp_create_event` | Create events pre-tagged with ATT&CK techniques |
| `mitre_misp_list_events` | List events with ATT&CK enrichment |

### Cross-Stack Correlation (2)

| Tool | Description |
|------|-------------|
| `mitre_soc_status` | Connection status for all SOC integrations |
| `mitre_cross_correlate` | Search for techniques across Wazuh, TheHive, and MISP simultaneously |

## Resource Reference

| URI | Description |
|-----|-------------|
| `mitre://matrix/enterprise` | Full Enterprise ATT&CK matrix (tactics x techniques) |
| `mitre://version` | Current data version and statistics |
| `mitre://tactics` | All tactics in kill-chain order |

## Prompt Reference

| Prompt | Description |
|--------|-------------|
| `map-incident-to-attack` | Map incident observables to ATT&CK techniques |
| `threat-hunt-plan` | Generate a threat hunting plan |
| `gap-analysis` | Perform detection gap analysis |
| `attribution-analysis` | Assist with threat attribution |

## Examples

### Check SOC integration status

```
Use mitre_soc_status to check which SOC platforms are connected.
```

### Map a Wazuh alert to ATT&CK

```
Use mitre_map_wazuh_alert with ruleId 5710 and ruleGroups ["sshd", "authentication_failed"]
to find matching ATT&CK techniques.
```

### Create an ATT&CK-enriched TheHive case

```
Use mitre_thehive_create_case with title "Suspected APT28 Activity",
techniques ["T1059.001", "T1566.001", "T1078"] and severity 3
to create a case with ATT&CK context, mitigations, and investigation tasks.
```

### Generate a Navigator coverage layer

```
Use mitre_navigator_layer with mode "coverage" and
dataSources ["Process", "Network Traffic", "File"]
to generate a heatmap of detection coverage.
```

### Cross-correlate across the SOC stack

```
Use mitre_cross_correlate with techniques ["T1059.001", "T1566.001"]
to search for related alerts in Wazuh, cases in TheHive, and events in MISP.
```

### Map a MISP event to ATT&CK

```
Use mitre_misp_event_to_attack with eventId "1"
to extract ATT&CK techniques from MISP galaxies and attributes.
```

### Compare two threat groups

```
Use mitre_navigator_layer with mode "diff" and
compareGroupIds ["G0007", "G0016"]
to generate a visual comparison of APT28 vs APT29 techniques.
```

## Testing

```bash
npm test            # Run all tests
npm run test:watch  # Watch mode
npm run lint        # Type check
```

## Project Structure

```
mitre-mcp/
  src/
    index.ts              # MCP server entry point
    config.ts             # Environment config (core + SOC)
    types.ts              # STIX/ATT&CK type definitions
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
    data/
      loader.ts           # STIX bundle downloader and cache manager
      parser.ts           # STIX 2.1 JSON parser (incl. campaigns)
      index.ts            # Indexed, queryable ATT&CK data store
    tools/
      techniques.ts       # Technique lookup and search
      tactics.ts          # Tactic navigation
      groups.ts           # Threat group intelligence
      software.ts         # Software/malware lookup
      mitigations.ts      # Mitigation mapping
      datasources.ts      # Data source and detection coverage
      mapping.ts          # Alert-to-technique mapping and correlation
      campaigns.ts        # Campaign analysis and attribution
      navigator.ts        # ATT&CK Navigator layer generation
      management.ts       # Data update management
    soc/
      client.ts           # HTTP clients for Wazuh, TheHive, Cortex, MISP
      wazuh.ts            # Wazuh alert mapping and rule coverage
      thehive.ts          # TheHive case enrichment and creation
      cortex.ts           # Cortex analyzer coverage mapping
      misp.ts             # MISP event/IOC management
      correlation.ts      # Cross-stack ATT&CK correlation
      index.ts            # SOC module barrel export
  tests/
    parser.test.ts        # STIX parser tests
    tools.test.ts         # Data store query tests
    mapping.test.ts       # Mapping and correlation tests
  package.json
  tsconfig.json
  tsup.config.ts
  vitest.config.ts
  README.md
```

## Data Sources

ATT&CK data is sourced from the official MITRE STIX 2.1 bundles:

- **Enterprise ATT&CK**: Windows, Linux, macOS, Cloud, Network, Containers
- **Mobile ATT&CK**: Android and iOS
- **ICS ATT&CK**: Industrial control systems

Data is downloaded on first run and cached locally. Set `MITRE_UPDATE_INTERVAL` to control how often the server checks for updates.

## License

MIT
