// STIX 2.1 base types for MITRE ATT&CK data

export interface StixObject {
  id: string;
  type: string;
  created: string;
  modified: string;
  name?: string;
  description?: string;
  external_references?: StixExternalReference[];
  object_marking_refs?: string[];
  x_mitre_deprecated?: boolean;
  revoked?: boolean;
  x_mitre_version?: string;
}

export interface StixExternalReference {
  source_name: string;
  external_id?: string;
  url?: string;
  description?: string;
}

export interface StixKillChainPhase {
  kill_chain_name: string;
  phase_name: string;
}

export interface StixRelationship extends StixObject {
  type: "relationship";
  relationship_type: string;
  source_ref: string;
  target_ref: string;
}

export interface StixBundle {
  type: "bundle";
  id: string;
  objects: StixObject[];
}

// ATT&CK-specific STIX object types

export interface StixAttackPattern extends StixObject {
  type: "attack-pattern";
  kill_chain_phases?: StixKillChainPhase[];
  x_mitre_platforms?: string[];
  x_mitre_data_sources?: string[];
  x_mitre_detection?: string;
  x_mitre_is_subtechnique?: boolean;
  x_mitre_system_requirements?: string[];
  x_mitre_permissions_required?: string[];
}

export interface StixTactic extends StixObject {
  type: "x-mitre-tactic";
  x_mitre_shortname?: string;
}

export interface StixIntrusionSet extends StixObject {
  type: "intrusion-set";
  aliases?: string[];
}

export interface StixMalware extends StixObject {
  type: "malware";
  aliases?: string[];
  x_mitre_platforms?: string[];
  is_family?: boolean;
  malware_types?: string[];
}

export interface StixTool extends StixObject {
  type: "tool";
  aliases?: string[];
  x_mitre_platforms?: string[];
}

export interface StixCourseOfAction extends StixObject {
  type: "course-of-action";
}

export interface StixDataSource extends StixObject {
  type: "x-mitre-data-source";
  x_mitre_platforms?: string[];
}

export interface StixDataComponent extends StixObject {
  type: "x-mitre-data-component";
  x_mitre_data_source_ref?: string;
}

export interface StixCampaign extends StixObject {
  type: "campaign";
  aliases?: string[];
  first_seen?: string;
  last_seen?: string;
}

// Parsed/indexed ATT&CK types (used by tools)

export interface AttackTechnique {
  id: string;
  stixId: string;
  name: string;
  description: string;
  tactics: string[];
  platforms: string[];
  dataSources: string[];
  detection: string;
  isSubtechnique: boolean;
  parentId: string | null;
  deprecated: boolean;
  revoked: boolean;
  references: AttackReference[];
}

export interface AttackTactic {
  id: string;
  stixId: string;
  name: string;
  shortName: string;
  description: string;
  order: number;
}

export interface AttackGroup {
  id: string;
  stixId: string;
  name: string;
  aliases: string[];
  description: string;
  deprecated: boolean;
  revoked: boolean;
  references: AttackReference[];
}

export interface AttackSoftware {
  id: string;
  stixId: string;
  name: string;
  type: "malware" | "tool";
  aliases: string[];
  description: string;
  platforms: string[];
  deprecated: boolean;
  revoked: boolean;
  references: AttackReference[];
}

export interface AttackMitigation {
  id: string;
  stixId: string;
  name: string;
  description: string;
  deprecated: boolean;
  revoked: boolean;
  references: AttackReference[];
}

export interface AttackDataSource {
  id: string;
  stixId: string;
  name: string;
  description: string;
  platforms: string[];
  references: AttackReference[];
}

export interface AttackDataComponent {
  id: string;
  stixId: string;
  name: string;
  description: string;
  dataSourceId: string;
}

export interface AttackRelationship {
  sourceRef: string;
  targetRef: string;
  relationshipType: string;
  description: string;
}

export interface AttackReference {
  source: string;
  url?: string;
}

// Kill chain ordering for enterprise matrix
export const ENTERPRISE_TACTIC_ORDER: Record<string, number> = {
  "reconnaissance": 0,
  "resource-development": 1,
  "initial-access": 2,
  "execution": 3,
  "persistence": 4,
  "privilege-escalation": 5,
  "defense-evasion": 6,
  "credential-access": 7,
  "discovery": 8,
  "lateral-movement": 9,
  "collection": 10,
  "command-and-control": 11,
  "exfiltration": 12,
  "impact": 13,
};

export type MatrixType = "enterprise" | "mobile" | "ics";

// Parsed campaign type
export interface AttackCampaign {
  id: string;
  stixId: string;
  name: string;
  description: string;
  aliases: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  deprecated: boolean;
  revoked: boolean;
  references: AttackReference[];
}

// Navigator layer types
export interface NavigatorLayer {
  name: string;
  versions: {
    attack: string;
    navigator: string;
    layer: string;
  };
  domain: string;
  description: string;
  filters: {
    platforms: string[];
  };
  sorting: number;
  layout: {
    layout: string;
    aggregateFunction: string;
    showID: boolean;
    showName: boolean;
    showAggregateScores: boolean;
    countUnscored: boolean;
  };
  hideDisabled: boolean;
  techniques: NavigatorTechniqueEntry[];
  gradient: {
    colors: string[];
    minValue: number;
    maxValue: number;
  };
  legendItems: NavigatorLegendItem[];
  metadata: Array<{ name: string; value: string }>;
  links: Array<{ label: string; url: string }>;
  showTacticRowBackground: boolean;
  tacticRowBackground: string;
  selectTechniquesAcrossTactics: boolean;
  selectSubtechniquesWithParent: boolean;
  selectVisibleTechniques: boolean;
}

export interface NavigatorTechniqueEntry {
  techniqueID: string;
  tactic?: string;
  color: string;
  comment: string;
  enabled: boolean;
  metadata: Array<{ name: string; value: string }>;
  links: Array<{ label: string; url: string }>;
  showSubtechniques: boolean;
  score?: number;
}

export interface NavigatorLegendItem {
  label: string;
  color: string;
}

// SOC integration config
export interface SocConfig {
  wazuh?: {
    url: string;
    username: string;
    password: string;
    verifySsl: boolean;
  };
  thehive?: {
    url: string;
    apiKey: string;
  };
  cortex?: {
    url: string;
    apiKey: string;
  };
  misp?: {
    url: string;
    apiKey: string;
    verifySsl: boolean;
  };
}

export interface MitreConfig {
  dataDir: string;
  matrices: MatrixType[];
  updateInterval: number;
  soc: SocConfig;
}
