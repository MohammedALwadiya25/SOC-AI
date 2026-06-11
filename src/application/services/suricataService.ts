import type { WazuhIndexerClient } from "../ports.js";
import { buildSearchBody, SURICATA_IP_FIELDS, SURICATA_SOURCE_FIELDS, type FilterClause } from "../queryBuilder.js";
import { normalizeSuricataAlert } from "../normalizers.js";
import type { SuricataAlert, TimeRange } from "../../domain/models.js";
import { bucketTimestamp, defaultTimeRange } from "../../utils/time.js";
import { effectiveLimit, type ServiceContext } from "./context.js";

export interface SuricataSearchInput {
  timeRange?: TimeRange;
  limit?: number;
  filters?: {
    sourceIp?: string;
    destinationIp?: string;
    signature?: string;
    signatureId?: string;
    category?: string;
    severityMin?: number;
  };
}

export interface CountBucket {
  key: string;
  count: number;
}

export interface TalkerBucket {
  sourceIp: string;
  destinationIp: string;
  count: number;
}

export interface TimelineBucket {
  bucketStart: string;
  count: number;
}

export class SuricataService {
  public constructor(
    private readonly indexer: WazuhIndexerClient,
    private readonly context: ServiceContext,
  ) {}

  public async getAlerts(input: SuricataSearchInput): Promise<{ alerts: SuricataAlert[]; total: number }> {
    const filters: FilterClause[] = [
      { field: "rule.groups", value: "suricata", operator: "match" },
    ];

    if (input.filters?.sourceIp) {
      filters.push({ field: "data.src_ip", value: input.filters.sourceIp, operator: "term" });
    }
    if (input.filters?.destinationIp) {
      filters.push({ field: "data.dest_ip", value: input.filters.destinationIp, operator: "term" });
    }
    if (input.filters?.signature) {
      filters.push({ field: "data.alert.signature", value: input.filters.signature, operator: "match" });
    }
    if (input.filters?.signatureId) {
      filters.push({ field: "data.alert.signature_id", value: input.filters.signatureId, operator: "term" });
    }
    if (input.filters?.category) {
      filters.push({ field: "data.alert.category", value: input.filters.category, operator: "match" });
    }
    if (input.filters?.severityMin !== undefined) {
      filters.push({ field: "data.alert.severity", value: input.filters.severityMin, operator: "range_gte" });
    }

    const response = await this.indexer.search({
      index: this.context.config.suricataIndex,
      body: buildSearchBody({
        timeRange: input.timeRange ?? defaultTimeRange(this.context.config.defaultTimeRangeHours),
        limit: effectiveLimit(input.limit, this.context),
        filters,
        ip: input.filters?.sourceIp ?? input.filters?.destinationIp,
        ipFields: [...SURICATA_IP_FIELDS],
        sourceFields: [...SURICATA_SOURCE_FIELDS],
      }),
    });

    return {
      total: response.total,
      alerts: response.hits.map((hit) => normalizeSuricataAlert(hit.id, hit.source)),
    };
  }

  public async getTopSignatures(input: { timeRange?: TimeRange; limit?: number }): Promise<CountBucket[]> {
    const result = await this.getAlerts({ timeRange: input.timeRange, limit: this.context.config.maxLimit });
    return topCounts(
      result.alerts.map((alert) => alert.signature ?? "unknown"),
      input.limit ?? 10,
    );
  }

  public async getTopTalkers(input: { timeRange?: TimeRange; limit?: number }): Promise<TalkerBucket[]> {
    const result = await this.getAlerts({ timeRange: input.timeRange, limit: this.context.config.maxLimit });
    const counts = new Map<string, TalkerBucket>();
    for (const alert of result.alerts) {
      const sourceIp = alert.sourceIp ?? "unknown";
      const destinationIp = alert.destinationIp ?? "unknown";
      const key = `${sourceIp}>${destinationIp}`;
      const existing = counts.get(key);
      counts.set(key, {
        sourceIp,
        destinationIp,
        count: (existing?.count ?? 0) + 1,
      });
    }
    return [...counts.values()].sort((left, right) => right.count - left.count).slice(0, input.limit ?? 10);
  }

  public async timeline(input: { timeRange?: TimeRange; bucketSizeMinutes: number; limit?: number }): Promise<TimelineBucket[]> {
    const result = await this.getAlerts({ timeRange: input.timeRange, limit: this.context.config.maxLimit });
    const counts = new Map<string, number>();
    for (const alert of result.alerts) {
      const bucket = bucketTimestamp(alert.timestamp, input.bucketSizeMinutes);
      counts.set(bucket, (counts.get(bucket) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([bucketStart, count]) => ({ bucketStart, count }))
      .sort((left, right) => Date.parse(left.bucketStart) - Date.parse(right.bucketStart))
      .slice(0, input.limit ?? 100);
  }
}

function topCounts(values: string[], limit: number): CountBucket[] {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, limit);
}
