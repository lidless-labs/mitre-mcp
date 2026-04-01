import type {
  AttackCampaign,
  AttackDataComponent,
  AttackDataSource,
  AttackGroup,
  AttackMitigation,
  AttackReference,
  AttackRelationship,
  AttackSoftware,
  AttackTactic,
  AttackTechnique,
  ENTERPRISE_TACTIC_ORDER,
  StixAttackPattern,
  StixBundle,
  StixCampaign,
  StixCourseOfAction,
  StixDataComponent,
  StixDataSource,
  StixExternalReference,
  StixIntrusionSet,
  StixMalware,
  StixObject,
  StixRelationship,
  StixTactic,
  StixTool,
} from "../types.js";

function getExternalId(refs?: StixExternalReference[]): string {
  if (!refs) return "";
  const mitreRef = refs.find((r) => r.source_name === "mitre-attack");
  return mitreRef?.external_id || "";
}

function parseReferences(refs?: StixExternalReference[]): AttackReference[] {
  if (!refs) return [];
  return refs
    .filter((r) => r.url)
    .map((r) => ({ source: r.source_name, url: r.url }));
}

export function parseTechniques(bundle: StixBundle): AttackTechnique[] {
  const attackPatterns = bundle.objects.filter(
    (obj): obj is StixAttackPattern =>
      obj.type === "attack-pattern" && !!obj.name,
  );

  return attackPatterns.map((ap) => {
    const id = getExternalId(ap.external_references);
    const tactics = (ap.kill_chain_phases || [])
      .filter((kc) => kc.kill_chain_name.includes("attack"))
      .map((kc) => kc.phase_name);

    const isSubtechnique = ap.x_mitre_is_subtechnique === true || id.includes(".");
    const parentId = isSubtechnique ? id.split(".")[0] : null;

    return {
      id,
      stixId: ap.id,
      name: ap.name || "",
      description: ap.description || "",
      tactics,
      platforms: ap.x_mitre_platforms || [],
      dataSources: ap.x_mitre_data_sources || [],
      detection: ap.x_mitre_detection || "",
      isSubtechnique,
      parentId,
      deprecated: ap.x_mitre_deprecated === true,
      revoked: ap.revoked === true,
      references: parseReferences(ap.external_references),
    };
  });
}

export function parseTactics(
  bundle: StixBundle,
  tacticOrder: Record<string, number>,
): AttackTactic[] {
  const tactics = bundle.objects.filter(
    (obj): obj is StixTactic => obj.type === "x-mitre-tactic" && !!obj.name,
  );

  return tactics
    .map((t) => {
      const id = getExternalId(t.external_references);
      const shortName = t.x_mitre_shortname || "";
      return {
        id,
        stixId: t.id,
        name: t.name || "",
        shortName,
        description: t.description || "",
        order: tacticOrder[shortName] ?? 99,
      };
    })
    .sort((a, b) => a.order - b.order);
}

export function parseGroups(bundle: StixBundle): AttackGroup[] {
  const groups = bundle.objects.filter(
    (obj): obj is StixIntrusionSet =>
      obj.type === "intrusion-set" && !!obj.name,
  );

  return groups.map((g) => ({
    id: getExternalId(g.external_references),
    stixId: g.id,
    name: g.name || "",
    aliases: g.aliases || [],
    description: g.description || "",
    deprecated: g.x_mitre_deprecated === true,
    revoked: g.revoked === true,
    references: parseReferences(g.external_references),
  }));
}

export function parseSoftware(bundle: StixBundle): AttackSoftware[] {
  const malware = bundle.objects.filter(
    (obj): obj is StixMalware => obj.type === "malware" && !!obj.name,
  );

  const tools = bundle.objects.filter(
    (obj): obj is StixTool => obj.type === "tool" && !!obj.name,
  );

  const software: AttackSoftware[] = [
    ...malware.map((m) => ({
      id: getExternalId(m.external_references),
      stixId: m.id,
      name: m.name || "",
      type: "malware" as const,
      aliases: m.aliases || [],
      description: m.description || "",
      platforms: m.x_mitre_platforms || [],
      deprecated: m.x_mitre_deprecated === true,
      revoked: m.revoked === true,
      references: parseReferences(m.external_references),
    })),
    ...tools.map((t) => ({
      id: getExternalId(t.external_references),
      stixId: t.id,
      name: t.name || "",
      type: "tool" as const,
      aliases: t.aliases || [],
      description: t.description || "",
      platforms: t.x_mitre_platforms || [],
      deprecated: t.x_mitre_deprecated === true,
      revoked: t.revoked === true,
      references: parseReferences(t.external_references),
    })),
  ];

  return software;
}

export function parseMitigations(bundle: StixBundle): AttackMitigation[] {
  const coas = bundle.objects.filter(
    (obj): obj is StixCourseOfAction =>
      obj.type === "course-of-action" && !!obj.name,
  );

  return coas.map((c) => ({
    id: getExternalId(c.external_references),
    stixId: c.id,
    name: c.name || "",
    description: c.description || "",
    deprecated: c.x_mitre_deprecated === true,
    revoked: c.revoked === true,
    references: parseReferences(c.external_references),
  }));
}

export function parseDataSources(bundle: StixBundle): AttackDataSource[] {
  const sources = bundle.objects.filter(
    (obj): obj is StixDataSource =>
      obj.type === "x-mitre-data-source" && !!obj.name,
  );

  return sources.map((ds) => ({
    id: getExternalId(ds.external_references),
    stixId: ds.id,
    name: ds.name || "",
    description: ds.description || "",
    platforms: ds.x_mitre_platforms || [],
    references: parseReferences(ds.external_references),
  }));
}

export function parseDataComponents(
  bundle: StixBundle,
): AttackDataComponent[] {
  const components = bundle.objects.filter(
    (obj): obj is StixDataComponent =>
      obj.type === "x-mitre-data-component" && !!obj.name,
  );

  return components.map((dc) => ({
    id: dc.id,
    stixId: dc.id,
    name: dc.name || "",
    description: dc.description || "",
    dataSourceId: dc.x_mitre_data_source_ref || "",
  }));
}

export function parseCampaigns(bundle: StixBundle): AttackCampaign[] {
  const campaigns = bundle.objects.filter(
    (obj): obj is StixCampaign => obj.type === "campaign" && !!obj.name,
  );

  return campaigns.map((c) => ({
    id: getExternalId(c.external_references),
    stixId: c.id,
    name: c.name || "",
    description: c.description || "",
    aliases: c.aliases || [],
    firstSeen: c.first_seen || null,
    lastSeen: c.last_seen || null,
    deprecated: c.x_mitre_deprecated === true,
    revoked: c.revoked === true,
    references: parseReferences(c.external_references),
  }));
}

export function parseRelationships(bundle: StixBundle): AttackRelationship[] {
  const rels = bundle.objects.filter(
    (obj): obj is StixRelationship => obj.type === "relationship",
  );

  return rels
    .filter((r) => !r.x_mitre_deprecated && !r.revoked)
    .map((r) => ({
      sourceRef: r.source_ref,
      targetRef: r.target_ref,
      relationshipType: r.relationship_type,
      description: r.description || "",
    }));
}
