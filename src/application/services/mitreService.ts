import type { AlertService } from "./alertService.js";
import { getTechniqueById, MITRE_CATALOG } from "./mitreCatalog.js";
import type { MitreMapping, MitreTechnique, NormalizedAlert } from "../../domain/models.js";
import { AppError, ERROR_CODES } from "../../domain/errors.js";

export class MitreService {
  public constructor(private readonly alertService: AlertService) {}

  public async mapAlert(input: { alertId?: string; alert?: Record<string, unknown> | NormalizedAlert }): Promise<MitreMapping> {
    const alert = input.alert ? coerceAlert(input.alert) : input.alertId ? await this.alertService.getAlertById(input.alertId) : null;
    if (!alert) {
      throw new AppError(ERROR_CODES.VALIDATION, "Either alertId or alert is required.");
    }

    const directTechniqueIds = alert.rule?.mitre?.map((technique) => technique.id).filter(Boolean) ?? [];
    const directTechniques = directTechniqueIds
      .map((id) => getTechniqueById(id) ?? fallbackTechniqueFromReference(id, alert))
      .filter((technique): technique is MitreTechnique => technique !== undefined);

    if (directTechniques.length > 0) {
      return {
        alertId: alert.id,
        techniques: uniqueTechniques(directTechniques),
        confidence: "high",
        reason: "Mapped from Wazuh rule.mitre fields.",
      };
    }

    const fallback = fallbackMapping(alert);
    return {
      alertId: alert.id,
      techniques: fallback.techniques,
      confidence: fallback.techniques.length > 0 ? "medium" : "low",
      reason: fallback.reason,
    };
  }

  public getTechnique(techniqueId: string): MitreTechnique {
    const technique = getTechniqueById(techniqueId);
    if (!technique) {
      throw new AppError(ERROR_CODES.NOT_FOUND, "MITRE technique was not found in the local V1 catalog.", {
        techniqueId,
      });
    }
    return technique;
  }

  public async ruleCoverage(input: { ruleId?: string; group?: string; limit?: number }): Promise<{
    totalRulesReviewed: number;
    mappedRules: number;
    unmappedRules: number;
    techniques: MitreTechnique[];
    note: string;
  }> {
    const result = await this.alertService.searchAlerts({
      ruleId: input.ruleId,
      keyword: input.group,
      limit: input.limit ?? 50,
    });
    const mappings = await Promise.all(result.alerts.map((alert) => this.mapAlert({ alert })));
    const mapped = mappings.filter((mapping) => mapping.techniques.length > 0);
    return {
      totalRulesReviewed: result.alerts.length,
      mappedRules: mapped.length,
      unmappedRules: result.alerts.length - mapped.length,
      techniques: uniqueTechniques(mapped.flatMap((mapping) => mapping.techniques)),
      note: "Coverage is estimated from recent Wazuh alerts and local fallback mappings.",
    };
  }
}

function coerceAlert(value: Record<string, unknown> | NormalizedAlert): NormalizedAlert {
  if ("severityScore" in value && "timestamp" in value && "id" in value) {
    return value as NormalizedAlert;
  }
  return {
    id: typeof value.id === "string" ? value.id : "inline-alert",
    timestamp: typeof value.timestamp === "string" ? value.timestamp : new Date(0).toISOString(),
    severity: "unknown",
    severityScore: 0,
    source: "unknown",
    normalizedFields: {},
    rule:
      typeof value.rule === "object" && value.rule !== null
        ? (value.rule as NormalizedAlert["rule"])
        : undefined,
  };
}

function fallbackTechniqueFromReference(id: string, alert: NormalizedAlert): MitreTechnique | undefined {
  const reference = alert.rule?.mitre?.find((technique) => technique.id === id);
  if (!reference) {
    return undefined;
  }
  return {
    id,
    name: reference.name ?? id,
    tactic: reference.tactic ?? "Unknown",
    description: "Technique metadata came from Wazuh alert fields.",
    url: `https://attack.mitre.org/techniques/${id}/`,
  };
}

function fallbackMapping(alert: NormalizedAlert): { techniques: MitreTechnique[]; reason: string } {
  const text = `${alert.rule?.description ?? ""} ${alert.rule?.groups?.join(" ") ?? ""}`.toLowerCase();
  const matches: MitreTechnique[] = [];

  if (text.includes("brute") || text.includes("authentication") || text.includes("login failed")) {
    matches.push(requiredTechnique("T1110"));
  }
  if (text.includes("command") || text.includes("powershell") || text.includes("shell")) {
    matches.push(requiredTechnique("T1059"));
  }
  if (text.includes("scan") || text.includes("service discovery") || text.includes("nmap")) {
    matches.push(requiredTechnique("T1046"));
  }
  if (text.includes("dns") || text.includes("http") || text.includes("beacon")) {
    matches.push(requiredTechnique("T1071"));
  }
  if (text.includes("valid account") || text.includes("successful login")) {
    matches.push(requiredTechnique("T1078"));
  }

  return {
    techniques: uniqueTechniques(matches),
    reason: matches.length > 0 ? "Mapped from rule text and groups fallback logic." : "No direct MITRE fields or reliable fallback match found.",
  };
}

function requiredTechnique(id: string): MitreTechnique {
  const technique = getTechniqueById(id);
  if (!technique) {
    throw new AppError(ERROR_CODES.INTERNAL, "MITRE catalog is missing a required fallback technique.");
  }
  return technique;
}

function uniqueTechniques(techniques: MitreTechnique[]): MitreTechnique[] {
  const byId = new Map<string, MitreTechnique>();
  for (const technique of techniques) {
    byId.set(technique.id, technique);
  }
  return [...byId.values()];
}

export function catalogTechniques(): MitreTechnique[] {
  return [...MITRE_CATALOG];
}
