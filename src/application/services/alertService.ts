import type { WazuhIndexerClient } from "../ports.js";
import {
  ALERT_IP_FIELDS,
  ALERT_KEYWORD_FIELDS,
  ALERT_SOURCE_FIELDS,
  buildSearchBody,
  type FilterClause,
} from "../queryBuilder.js";
import { normalizeAlert } from "../normalizers.js";
import type { NormalizedAlert, TimeRange } from "../../domain/models.js";
import { AppError, ERROR_CODES } from "../../domain/errors.js";
import { defaultTimeRange } from "../../utils/time.js";
import { effectiveLimit, type ServiceContext } from "./context.js";

export interface AlertSearchInput {
  timeRange?: TimeRange;
  limit?: number;
  keyword?: string;
  severityMin?: number;
  agentId?: string;
  ruleId?: string;
  ip?: string;
}

export class AlertService {
  public constructor(
    private readonly indexer: WazuhIndexerClient,
    private readonly context: ServiceContext,
  ) {}

  public async getAlerts(input: { timeRange?: TimeRange; limit?: number }): Promise<{ alerts: NormalizedAlert[]; total: number }> {
    return this.searchAlerts(input);
  }

  public async searchAlerts(input: AlertSearchInput): Promise<{ alerts: NormalizedAlert[]; total: number }> {
    const filters: FilterClause[] = [];
    if (input.severityMin !== undefined) {
      filters.push({ field: "rule.level", value: input.severityMin, operator: "range_gte" });
    }
    if (input.agentId) {
      filters.push({ field: "agent.id", value: input.agentId, operator: "term" });
    }
    if (input.ruleId) {
      filters.push({ field: "rule.id", value: input.ruleId, operator: "term" });
    }

    const response = await this.indexer.search({
      index: this.context.config.alertIndex,
      body: buildSearchBody({
        timeRange: input.timeRange ?? defaultTimeRange(this.context.config.defaultTimeRangeHours),
        limit: effectiveLimit(input.limit, this.context),
        filters,
        keyword: input.keyword,
        keywordFields: [...ALERT_KEYWORD_FIELDS],
        ip: input.ip,
        ipFields: [...ALERT_IP_FIELDS],
        sourceFields: [...ALERT_SOURCE_FIELDS],
      }),
    });

    return {
      total: response.total,
      alerts: response.hits.map((hit) => normalizeAlert(hit.id, hit.source)),
    };
  }

  public async getAlertById(alertId: string): Promise<NormalizedAlert> {
    const response = await this.indexer.search({
      index: this.context.config.alertIndex,
      body: buildSearchBody({
        ids: [alertId],
        limit: 1,
        sourceFields: [...ALERT_SOURCE_FIELDS],
      }),
    });

    const hit = response.hits[0];
    if (!hit) {
      throw new AppError(ERROR_CODES.NOT_FOUND, "Alert was not found.", { alertId });
    }
    return normalizeAlert(hit.id, hit.source);
  }

  public async getHighSeverityAlerts(input: { timeRange?: TimeRange; severityMin?: number; limit?: number }): Promise<{
    alerts: NormalizedAlert[];
    total: number;
  }> {
    return this.searchAlerts({
      ...input,
      severityMin: input.severityMin ?? 10,
    });
  }
}
