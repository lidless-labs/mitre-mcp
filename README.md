# MITRE ATT&CK MCP Server

[![TypeScript 5.7](https://img.shields.io/badge/TypeScript-5.7-blue)](https://www.typescriptlang.org/)
[![Node.js 20+](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org/)
[![MCP 1.x](https://img.shields.io/badge/MCP-1.x-purple)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

An MCP server providing comprehensive access to the MITRE ATT&CK knowledge base. Enables LLMs to look up techniques, map alerts to ATT&CK, analyze detection coverage, profile campaigns, and generate threat intelligence context.

## Features

- **19 tools** for technique lookup, tactic navigation, group intelligence, software analysis, mitigation mapping, detection coverage, alert mapping, campaign profiling, and data management
- **3 resources** for matrix overview, version info, and tactic listing
- **4 prompts** for incident mapping, threat hunting, gap analysis, and attribution
- **Offline-capable** with local STIX 2.1 data caching
- **Auto-updating** with configurable refresh intervals
- **Enterprise, Mobile, and ICS** matrix support

## Prerequisites

- Node.js 20 or later
- Internet access for initial ATT&CK data download (cached locally after first run)

## Installation

```bash
git clone https://github.com/solomonneas/mitre-mcp.git
cd mitre-mcp
npm install
npm run build
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MITRE_DATA_DIR` | `~/.mitre-mcp/data` | Local cache directory for STIX bundles |
| `MITRE_MATRICES` | `enterprise` | Comma-separated matrices: `enterprise`, `mobile`, `ics` |
| `MITRE_UPDATE_INTERVAL` | `86400` | Auto-update check interval in seconds (default 24h) |

## Usage

### Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "node",
      "args": ["/path/to/mitre-mcp/dist/index.js"],
      "env": {
        "MITRE_MATRICES": "enterprise"
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

### Technique Lookup

| Tool | Description |
|------|-------------|
| `mitre_get_technique` | Get full details of a technique by ID (T1059, T1059.001) |
| `mitre_search_techniques` | Search techniques by keyword, tactic, platform, data source |

### Tactic Navigation

| Tool | Description |
|------|-------------|
| `mitre_list_tactics` | List all tactics in kill-chain order |
| `mitre_get_tactic` | Get tactic details with all associated techniques |

### Threat Group Intelligence

| Tool | Description |
|------|-------------|
| `mitre_get_group` | Get group details including techniques and software used |
| `mitre_search_groups` | Search groups by keyword or technique usage |
| `mitre_list_groups` | List all known threat groups |

### Software & Malware

| Tool | Description |
|------|-------------|
| `mitre_get_software` | Get software details with techniques and associated groups |
| `mitre_search_software` | Search software by name, technique, or type (malware/tool) |

### Mitigation Mapping

| Tool | Description |
|------|-------------|
| `mitre_get_mitigation` | Get mitigation details with addressed techniques |
| `mitre_mitigations_for_technique` | Get all mitigations for a specific technique |
| `mitre_search_mitigations` | Search mitigations by keyword |

### Detection & Data Sources

| Tool | Description |
|------|-------------|
| `mitre_get_datasource` | Get data source details with components and detectable techniques |
| `mitre_detection_coverage` | Analyze detection coverage based on available data sources |

### Mapping & Correlation

| Tool | Description |
|------|-------------|
| `mitre_map_alert_to_technique` | Map security alerts to likely ATT&CK techniques with scoring |
| `mitre_technique_overlap` | Find technique overlap between groups for attribution |
| `mitre_attack_path` | Generate possible attack paths through the kill chain |

### Campaign Analysis

| Tool | Description |
|------|-------------|
| `mitre_campaign_profile` | Build a technique profile from observed techniques |

### Data Management

| Tool | Description |
|------|-------------|
| `mitre_update_data` | Force update of the local ATT&CK data cache |
| `mitre_data_version` | Get current data version and object counts |

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

### Look up a technique

```
Use mitre_get_technique with techniqueId "T1059.001" to get PowerShell technique details.
```

### Find techniques for a tactic

```
Use mitre_search_techniques with tactic "initial-access" to list all initial access techniques.
```

### Analyze detection coverage

```
Use mitre_detection_coverage with availableDataSources ["Process", "Network Traffic", "File"]
to see what percentage of techniques your environment can detect.
```

### Profile a campaign

```
Use mitre_campaign_profile with techniques ["T1059.001", "T1566.001", "T1078"]
to identify likely threat actors and recommended mitigations.
```

### Map an alert

```
Use mitre_map_alert_to_technique with alertType "PowerShell encoded command execution detected"
and platform "Windows" to find matching ATT&CK techniques.
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
    config.ts             # Environment config
    types.ts              # STIX/ATT&CK type definitions
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
    data/
      loader.ts           # STIX bundle downloader and cache manager
      parser.ts           # STIX 2.1 JSON parser
      index.ts            # Indexed, queryable ATT&CK data store
    tools/
      techniques.ts       # Technique lookup and search
      tactics.ts          # Tactic navigation
      groups.ts           # Threat group intelligence
      software.ts         # Software/malware lookup
      mitigations.ts      # Mitigation mapping
      datasources.ts      # Data source and detection coverage
      mapping.ts          # Alert-to-technique mapping and correlation
      campaigns.ts        # Campaign analysis
      management.ts       # Data update management
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

- **Enterprise ATT&CK** - Covers Windows, Linux, macOS, Cloud, Network, Containers
- **Mobile ATT&CK** - Covers Android and iOS
- **ICS ATT&CK** - Covers industrial control systems

Data is downloaded on first run and cached locally. Set `MITRE_UPDATE_INTERVAL` to control how often the server checks for updates.

## License

MIT
