import type {
  AttackCampaign,
  AttackDataComponent,
  AttackDataSource,
  AttackGroup,
  AttackMitigation,
  AttackRelationship,
  AttackSoftware,
  AttackTactic,
  AttackTechnique,
  MatrixType,
  MitreConfig,
  StixBundle,
} from "../types.js";
import { ENTERPRISE_TACTIC_ORDER } from "../types.js";
import {
  downloadAllMatrices,
  getLastUpdated,
  hasCachedData,
  isCacheStale,
  loadCachedBundles,
} from "./loader.js";
import {
  parseCampaigns,
  parseDataComponents,
  parseDataSources,
  parseGroups,
  parseMitigations,
  parseRelationships,
  parseSoftware,
  parseTactics,
  parseTechniques,
} from "./parser.js";

export class AttackDataStore {
  private techniques: Map<string, AttackTechnique> = new Map();
  private techniquesByStixId: Map<string, AttackTechnique> = new Map();
  private tactics: Map<string, AttackTactic> = new Map();
  private tacticsByShortName: Map<string, AttackTactic> = new Map();
  private groups: Map<string, AttackGroup> = new Map();
  private groupsByStixId: Map<string, AttackGroup> = new Map();
  private groupsByName: Map<string, AttackGroup> = new Map();
  private software: Map<string, AttackSoftware> = new Map();
  private softwareByStixId: Map<string, AttackSoftware> = new Map();
  private softwareByName: Map<string, AttackSoftware> = new Map();
  private mitigations: Map<string, AttackMitigation> = new Map();
  private mitigationsByStixId: Map<string, AttackMitigation> = new Map();
  private dataSources: Map<string, AttackDataSource> = new Map();
  private dataSourcesByStixId: Map<string, AttackDataSource> = new Map();
  private dataSourcesByName: Map<string, AttackDataSource> = new Map();
  private campaigns: Map<string, AttackCampaign> = new Map();
  private campaignsByStixId: Map<string, AttackCampaign> = new Map();
  private campaignsByName: Map<string, AttackCampaign> = new Map();
  private dataComponents: AttackDataComponent[] = [];
  private relationships: AttackRelationship[] = [];

  private config: MitreConfig;
  private loaded = false;

  constructor(config: MitreConfig) {
    this.config = config;
  }

  async initialize(): Promise<void> {
    const { dataDir, matrices, updateInterval } = this.config;

    let bundles: Map<MatrixType, StixBundle> | null = null;

    if (hasCachedData(dataDir, matrices) && !isCacheStale(dataDir, updateInterval)) {
      bundles = loadCachedBundles(dataDir, matrices);
    }

    if (!bundles) {
      try {
        bundles = await downloadAllMatrices(dataDir, matrices);
      } catch (error) {
        bundles = loadCachedBundles(dataDir, matrices);
        if (!bundles) {
          throw new Error(
            `Failed to load ATT&CK data: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
    }

    for (const [, bundle] of bundles) {
      this.indexBundle(bundle);
    }

    this.loaded = true;
  }

  loadFromBundles(bundles: Map<MatrixType, StixBundle>): void {
    for (const [, bundle] of bundles) {
      this.indexBundle(bundle);
    }
    this.loaded = true;
  }

  private indexBundle(bundle: StixBundle): void {
    const techniques = parseTechniques(bundle);
    for (const t of techniques) {
      this.techniques.set(t.id, t);
      this.techniquesByStixId.set(t.stixId, t);
    }

    const tactics = parseTactics(bundle, ENTERPRISE_TACTIC_ORDER);
    for (const t of tactics) {
      this.tactics.set(t.id, t);
      this.tacticsByShortName.set(t.shortName, t);
    }

    const groups = parseGroups(bundle);
    for (const g of groups) {
      this.groups.set(g.id, g);
      this.groupsByStixId.set(g.stixId, g);
      this.groupsByName.set(g.name.toLowerCase(), g);
      for (const alias of g.aliases) {
        this.groupsByName.set(alias.toLowerCase(), g);
      }
    }

    const software = parseSoftware(bundle);
    for (const s of software) {
      this.software.set(s.id, s);
      this.softwareByStixId.set(s.stixId, s);
      this.softwareByName.set(s.name.toLowerCase(), s);
      for (const alias of s.aliases) {
        this.softwareByName.set(alias.toLowerCase(), s);
      }
    }

    const mitigations = parseMitigations(bundle);
    for (const m of mitigations) {
      this.mitigations.set(m.id, m);
      this.mitigationsByStixId.set(m.stixId, m);
    }

    const dataSources = parseDataSources(bundle);
    for (const ds of dataSources) {
      this.dataSources.set(ds.id, ds);
      this.dataSourcesByStixId.set(ds.stixId, ds);
      this.dataSourcesByName.set(ds.name.toLowerCase(), ds);
    }

    const campaigns = parseCampaigns(bundle);
    for (const c of campaigns) {
      this.campaigns.set(c.id, c);
      this.campaignsByStixId.set(c.stixId, c);
      this.campaignsByName.set(c.name.toLowerCase(), c);
      for (const alias of c.aliases) {
        this.campaignsByName.set(alias.toLowerCase(), c);
      }
    }

    this.dataComponents.push(...parseDataComponents(bundle));
    this.relationships.push(...parseRelationships(bundle));
  }

  isLoaded(): boolean {
    return this.loaded;
  }

  // Technique queries

  getTechnique(id: string): AttackTechnique | undefined {
    return this.techniques.get(id.toUpperCase());
  }

  getTechniqueByStixId(stixId: string): AttackTechnique | undefined {
    return this.techniquesByStixId.get(stixId);
  }

  getAllTechniques(includeDeprecated = false): AttackTechnique[] {
    const all = Array.from(this.techniques.values());
    if (includeDeprecated) return all;
    return all.filter((t) => !t.deprecated && !t.revoked);
  }

  searchTechniques(opts: {
    query?: string;
    tactic?: string;
    platform?: string;
    dataSource?: string;
    isSubtechnique?: boolean;
  }): AttackTechnique[] {
    let results = this.getAllTechniques();

    if (opts.query) {
      const q = opts.query.toLowerCase();
      results = results.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q) ||
          t.id.toLowerCase().includes(q),
      );
    }

    if (opts.tactic) {
      const tactic = opts.tactic.toLowerCase();
      results = results.filter((t) =>
        t.tactics.some((ta) => ta.toLowerCase() === tactic),
      );
    }

    if (opts.platform) {
      const platform = opts.platform.toLowerCase();
      results = results.filter((t) =>
        t.platforms.some((p) => p.toLowerCase() === platform),
      );
    }

    if (opts.dataSource) {
      const ds = opts.dataSource.toLowerCase();
      results = results.filter((t) =>
        t.dataSources.some((d) => d.toLowerCase().includes(ds)),
      );
    }

    if (opts.isSubtechnique !== undefined) {
      results = results.filter(
        (t) => t.isSubtechnique === opts.isSubtechnique,
      );
    }

    return results;
  }

  getSubtechniques(parentId: string): AttackTechnique[] {
    return this.getAllTechniques().filter((t) => t.parentId === parentId.toUpperCase());
  }

  // Tactic queries

  getTactic(id: string): AttackTactic | undefined {
    return this.tactics.get(id.toUpperCase()) || this.tacticsByShortName.get(id.toLowerCase());
  }

  getAllTactics(): AttackTactic[] {
    return Array.from(this.tactics.values()).sort((a, b) => a.order - b.order);
  }

  getTechniquesForTactic(tacticShortName: string): AttackTechnique[] {
    const name = tacticShortName.toLowerCase();
    return this.getAllTechniques().filter((t) =>
      t.tactics.some((ta) => ta.toLowerCase() === name),
    );
  }

  // Group queries

  getGroup(idOrName: string): AttackGroup | undefined {
    return (
      this.groups.get(idOrName.toUpperCase()) ||
      this.groupsByName.get(idOrName.toLowerCase())
    );
  }

  getAllGroups(includeDeprecated = false): AttackGroup[] {
    const all = Array.from(this.groups.values());
    if (includeDeprecated) return all;
    return all.filter((g) => !g.deprecated && !g.revoked);
  }

  searchGroups(opts: { query?: string; technique?: string }): AttackGroup[] {
    let results = this.getAllGroups();

    if (opts.query) {
      const q = opts.query.toLowerCase();
      results = results.filter(
        (g) =>
          g.name.toLowerCase().includes(q) ||
          g.description.toLowerCase().includes(q) ||
          g.aliases.some((a) => a.toLowerCase().includes(q)),
      );
    }

    if (opts.technique) {
      const techStixId = this.techniques.get(opts.technique.toUpperCase())?.stixId;
      if (techStixId) {
        const groupStixIds = new Set(
          this.relationships
            .filter(
              (r) =>
                r.targetRef === techStixId && r.relationshipType === "uses",
            )
            .map((r) => r.sourceRef),
        );
        results = results.filter((g) => groupStixIds.has(g.stixId));
      } else {
        results = [];
      }
    }

    return results;
  }

  getGroupTechniques(
    groupStixId: string,
  ): Array<{ technique: AttackTechnique; usage: string }> {
    return this.relationships
      .filter(
        (r) => r.sourceRef === groupStixId && r.relationshipType === "uses",
      )
      .map((r) => {
        const technique = this.techniquesByStixId.get(r.targetRef);
        if (!technique || technique.deprecated || technique.revoked) return null;
        return { technique, usage: r.description };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  getGroupSoftware(
    groupStixId: string,
  ): Array<{ software: AttackSoftware }> {
    return this.relationships
      .filter(
        (r) => r.sourceRef === groupStixId && r.relationshipType === "uses",
      )
      .map((r) => {
        const sw = this.softwareByStixId.get(r.targetRef);
        if (!sw) return null;
        return { software: sw };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  // Software queries

  getSoftware(idOrName: string): AttackSoftware | undefined {
    return (
      this.software.get(idOrName.toUpperCase()) ||
      this.softwareByName.get(idOrName.toLowerCase())
    );
  }

  getAllSoftware(includeDeprecated = false): AttackSoftware[] {
    const all = Array.from(this.software.values());
    if (includeDeprecated) return all;
    return all.filter((s) => !s.deprecated && !s.revoked);
  }

  searchSoftware(opts: {
    query?: string;
    technique?: string;
    type?: "malware" | "tool";
  }): AttackSoftware[] {
    let results = this.getAllSoftware();

    if (opts.type) {
      results = results.filter((s) => s.type === opts.type);
    }

    if (opts.query) {
      const q = opts.query.toLowerCase();
      results = results.filter(
        (s) =>
          s.name.toLowerCase().includes(q) ||
          s.description.toLowerCase().includes(q) ||
          s.aliases.some((a) => a.toLowerCase().includes(q)),
      );
    }

    if (opts.technique) {
      const techStixId = this.techniques.get(opts.technique.toUpperCase())?.stixId;
      if (techStixId) {
        const swStixIds = new Set(
          this.relationships
            .filter(
              (r) =>
                r.targetRef === techStixId && r.relationshipType === "uses",
            )
            .map((r) => r.sourceRef),
        );
        results = results.filter((s) => swStixIds.has(s.stixId));
      } else {
        results = [];
      }
    }

    return results;
  }

  getSoftwareTechniques(
    swStixId: string,
  ): Array<{ technique: AttackTechnique; usage: string }> {
    return this.relationships
      .filter(
        (r) => r.sourceRef === swStixId && r.relationshipType === "uses",
      )
      .map((r) => {
        const technique = this.techniquesByStixId.get(r.targetRef);
        if (!technique || technique.deprecated || technique.revoked) return null;
        return { technique, usage: r.description };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  getSoftwareGroups(
    swStixId: string,
  ): Array<{ group: AttackGroup }> {
    return this.relationships
      .filter(
        (r) => r.targetRef === swStixId && r.relationshipType === "uses",
      )
      .map((r) => {
        const group = this.groupsByStixId.get(r.sourceRef);
        if (!group) return null;
        return { group };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  // Mitigation queries

  getMitigation(id: string): AttackMitigation | undefined {
    return this.mitigations.get(id.toUpperCase());
  }

  getAllMitigations(includeDeprecated = false): AttackMitigation[] {
    const all = Array.from(this.mitigations.values());
    if (includeDeprecated) return all;
    return all.filter((m) => !m.deprecated && !m.revoked);
  }

  searchMitigations(query: string): AttackMitigation[] {
    const q = query.toLowerCase();
    return this.getAllMitigations().filter(
      (m) =>
        m.name.toLowerCase().includes(q) ||
        m.description.toLowerCase().includes(q),
    );
  }

  getMitigationsForTechnique(
    techniqueId: string,
  ): Array<{ mitigation: AttackMitigation; description: string }> {
    const tech = this.techniques.get(techniqueId.toUpperCase());
    if (!tech) return [];

    return this.relationships
      .filter(
        (r) =>
          r.targetRef === tech.stixId && r.relationshipType === "mitigates",
      )
      .map((r) => {
        const mitigation = this.mitigationsByStixId.get(r.sourceRef);
        if (!mitigation || mitigation.deprecated || mitigation.revoked) return null;
        return { mitigation, description: r.description };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  getTechniquesForMitigation(
    mitigationId: string,
  ): Array<{ technique: AttackTechnique; description: string }> {
    const mit = this.mitigations.get(mitigationId.toUpperCase());
    if (!mit) return [];

    return this.relationships
      .filter(
        (r) =>
          r.sourceRef === mit.stixId && r.relationshipType === "mitigates",
      )
      .map((r) => {
        const technique = this.techniquesByStixId.get(r.targetRef);
        if (!technique || technique.deprecated || technique.revoked) return null;
        return { technique, description: r.description };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  // Data source queries

  getDataSource(idOrName: string): AttackDataSource | undefined {
    return (
      this.dataSources.get(idOrName.toUpperCase()) ||
      this.dataSourcesByName.get(idOrName.toLowerCase())
    );
  }

  getAllDataSources(): AttackDataSource[] {
    return Array.from(this.dataSources.values());
  }

  getDataComponents(): AttackDataComponent[] {
    return this.dataComponents;
  }

  getComponentsForDataSource(dsStixId: string): AttackDataComponent[] {
    return this.dataComponents.filter((dc) => dc.dataSourceId === dsStixId);
  }

  getTechniquesDetectedByComponent(
    componentStixId: string,
  ): AttackTechnique[] {
    const techStixIds = this.relationships
      .filter(
        (r) =>
          r.sourceRef === componentStixId && r.relationshipType === "detects",
      )
      .map((r) => r.targetRef);

    return techStixIds
      .map((id) => this.techniquesByStixId.get(id))
      .filter((t): t is AttackTechnique => !!t && !t.deprecated && !t.revoked);
  }

  // Campaign queries

  getCampaign(idOrName: string): AttackCampaign | undefined {
    return (
      this.campaigns.get(idOrName.toUpperCase()) ||
      this.campaignsByName.get(idOrName.toLowerCase())
    );
  }

  getAllCampaigns(includeDeprecated = false): AttackCampaign[] {
    const all = Array.from(this.campaigns.values());
    if (includeDeprecated) return all;
    return all.filter((c) => !c.deprecated && !c.revoked);
  }

  searchCampaigns(opts: { query?: string; technique?: string }): AttackCampaign[] {
    let results = this.getAllCampaigns();

    if (opts.query) {
      const q = opts.query.toLowerCase();
      results = results.filter(
        (c) =>
          c.name.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.aliases.some((a) => a.toLowerCase().includes(q)),
      );
    }

    if (opts.technique) {
      const techStixId = this.techniques.get(opts.technique.toUpperCase())?.stixId;
      if (techStixId) {
        const campaignStixIds = new Set(
          this.relationships
            .filter(
              (r) =>
                r.targetRef === techStixId && r.relationshipType === "uses",
            )
            .map((r) => r.sourceRef),
        );
        results = results.filter((c) => campaignStixIds.has(c.stixId));
      } else {
        results = [];
      }
    }

    return results;
  }

  getCampaignTechniques(
    campaignStixId: string,
  ): Array<{ technique: AttackTechnique; usage: string }> {
    return this.relationships
      .filter(
        (r) => r.sourceRef === campaignStixId && r.relationshipType === "uses",
      )
      .map((r) => {
        const technique = this.techniquesByStixId.get(r.targetRef);
        if (!technique || technique.deprecated || technique.revoked) return null;
        return { technique, usage: r.description };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  getCampaignSoftware(
    campaignStixId: string,
  ): Array<{ software: AttackSoftware }> {
    return this.relationships
      .filter(
        (r) => r.sourceRef === campaignStixId && r.relationshipType === "uses",
      )
      .map((r) => {
        const sw = this.softwareByStixId.get(r.targetRef);
        if (!sw) return null;
        return { software: sw };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
  }

  getCampaignsForGroup(groupStixId: string): AttackCampaign[] {
    const campaignStixIds = new Set(
      this.relationships
        .filter(
          (r) =>
            r.targetRef === groupStixId &&
            r.relationshipType === "attributed-to",
        )
        .map((r) => r.sourceRef),
    );
    return Array.from(campaignStixIds)
      .map((id) => this.campaignsByStixId.get(id))
      .filter((c): c is AttackCampaign => !!c && !c.deprecated && !c.revoked);
  }

  // Relationship helpers

  getRelationships(): AttackRelationship[] {
    return this.relationships;
  }

  getRelationshipsForObject(
    stixId: string,
    direction: "source" | "target" | "both" = "both",
  ): AttackRelationship[] {
    return this.relationships.filter((r) => {
      if (direction === "source") return r.sourceRef === stixId;
      if (direction === "target") return r.targetRef === stixId;
      return r.sourceRef === stixId || r.targetRef === stixId;
    });
  }

  // Stats

  getStats(): {
    techniques: number;
    tactics: number;
    groups: number;
    software: number;
    mitigations: number;
    dataSources: number;
    campaigns: number;
    relationships: number;
  } {
    return {
      techniques: this.getAllTechniques().length,
      tactics: this.getAllTactics().length,
      groups: this.getAllGroups().length,
      software: this.getAllSoftware().length,
      mitigations: this.getAllMitigations().length,
      dataSources: this.getAllDataSources().length,
      campaigns: this.getAllCampaigns().length,
      relationships: this.relationships.length,
    };
  }
}
