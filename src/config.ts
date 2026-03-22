import { homedir } from "node:os";
import { join } from "node:path";
import type { MatrixType, MitreConfig, SocConfig } from "./types.js";

const VALID_MATRICES = new Set(["enterprise", "mobile", "ics"]);

function loadSocConfig(): SocConfig {
  const soc: SocConfig = {};

  if (process.env.WAZUH_URL) {
    soc.wazuh = {
      url: process.env.WAZUH_URL,
      username: process.env.WAZUH_USERNAME || "wazuh-wui",
      password: process.env.WAZUH_PASSWORD || "",
      verifySsl: process.env.WAZUH_VERIFY_SSL !== "false",
    };
  }

  if (process.env.THEHIVE_URL) {
    soc.thehive = {
      url: process.env.THEHIVE_URL,
      apiKey: process.env.THEHIVE_API_KEY || "",
    };
  }

  if (process.env.CORTEX_URL) {
    soc.cortex = {
      url: process.env.CORTEX_URL,
      apiKey: process.env.CORTEX_API_KEY || "",
    };
  }

  if (process.env.MISP_URL) {
    soc.misp = {
      url: process.env.MISP_URL,
      apiKey: process.env.MISP_API_KEY || "",
      verifySsl: process.env.MISP_VERIFY_SSL !== "false",
    };
  }

  return soc;
}

export function loadConfig(): MitreConfig {
  const dataDir =
    process.env.MITRE_DATA_DIR || join(homedir(), ".mitre-mcp", "data");

  const matricesRaw = process.env.MITRE_MATRICES || "enterprise";
  const matrices = matricesRaw
    .split(",")
    .map((m) => m.trim().toLowerCase())
    .filter((m) => VALID_MATRICES.has(m)) as MatrixType[];

  if (matrices.length === 0) {
    matrices.push("enterprise");
  }

  const updateInterval = parseInt(
    process.env.MITRE_UPDATE_INTERVAL || "86400",
    10,
  );

  return {
    dataDir,
    matrices,
    updateInterval: isNaN(updateInterval) ? 86400 : updateInterval,
    soc: loadSocConfig(),
  };
}
