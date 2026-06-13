import type { WazuhIndexerClient } from "../ports.js";
import {
  buildSearchBody,
  type FilterClause,
  ZEEK_IP_FIELDS,
  ZEEK_SOURCE_FIELDS,
} from "../queryBuilder.js";
import { normalizeZeekEvent } from "../normalizers.js";
import type { TimeRange, ZeekEvent } from "../../domain/models.js";
import { defaultTimeRange } from "../../utils/time.js";
import { effectiveLimit, type ServiceContext } from "./context.js";

export interface ZeekSearchInput {
  timeRange?: TimeRange;
  limit?: number;
  logType?: "dns" | "conn" | "http" | "ssl" | "notice" | "files";
  filters?: {
    sourceIp?: string;
    destinationIp?: string;
    protocol?: string;
    service?: string;
    query?: string;
    answer?: string;
  };
}

export interface BeaconingFinding {
  sourceIp?: string;
  destinationIp?: string;
  eventCount: number;
  averageIntervalSeconds: number;
  jitterRatio: number;
  confidence: "low" | "medium" | "high";
}

export class ZeekService {
  public constructor(
    private readonly indexer: WazuhIndexerClient,
    private readonly context: ServiceContext,
  ) {}

  public async searchLogs(input: ZeekSearchInput): Promise<{ events: ZeekEvent[]; total: number }> {
    const filters: FilterClause[] = [
      { field: "location", value: "*zeek*", operator: "wildcard" },
    ];

    if (input.logType) {
      filters.push({ field: "rule.groups", value: input.logType, operator: "match" });
    }
   
    if (input.filters?.protocol) {
      filters.push({ field: "data.protocol", value: input.filters.protocol, operator: "term" });
    }
    if (input.filters?.service) {
      filters.push({ field: "data.service", value: input.filters.service, operator: "term" });
    }
    if (input.filters?.query) {
      filters.push({ field: "data.query", value: input.filters.query, operator: "term" });
    }
    if (input.filters?.answer) {
      filters.push({ field: "data.answers", value: input.filters.answer, operator: "match" });
    }
    
    if (input.logType) {
      const logTypeToLocation: Record<string, string> = {
        conn: "/opt/zeek/logs/current/conn.log",
        dns: "/opt/zeek/logs/current/dns.log",
        http: "/opt/zeek/logs/current/http.log",
        ssl: "/opt/zeek/logs/current/ssl.log",
        files: "/opt/zeek/logs/current/files.log",
        notice: "/opt/zeek/logs/current/notice.log",
      };
     const location = logTypeToLocation[input.logType];
     if (location) {
       filters.push({ field: "location", value: location, operator: "term" });
     }
   }
    const response = await this.indexer.search({
      index: this.context.config.zeekIndex,
      body: buildSearchBody({
        timeRange: input.timeRange ?? defaultTimeRange(this.context.config.defaultTimeRangeHours),
        limit: effectiveLimit(input.limit, this.context),
        filters,
        sourceFields: [...ZEEK_SOURCE_FIELDS],
        ip: input.filters?.sourceIp ?? input.filters?.destinationIp,
        ipFields: [...ZEEK_IP_FIELDS],
      }),
    });

    return {
      total: response.total,
      events: response.hits.map((hit) => normalizeZeekEvent(hit.id, hit.source)),
    };
  }

  public async getDnsActivity(input: Omit<ZeekSearchInput, "logType">): Promise<{ events: ZeekEvent[]; total: number }> {
    return this.searchLogs({ ...input, logType: "dns" });
  }

  public async getConnectionActivity(input: Omit<ZeekSearchInput, "logType">): Promise<{ events: ZeekEvent[]; total: number }> {
    return this.searchLogs({ ...input, logType: "conn" });
  }

  public async detectBeaconing(input: {
    timeRange?: TimeRange;
    sourceIp?: string;
    destinationIp?: string;
    limit?: number;
  }): Promise<BeaconingFinding[]> {
    const result = await this.getConnectionActivity({
      timeRange: input.timeRange,
      limit: Math.min(input.limit ?? this.context.config.maxLimit, this.context.config.maxLimit),
      filters: {
        sourceIp: input.sourceIp,
        destinationIp: input.destinationIp,
      },
    });

    const grouped = new Map<string, ZeekEvent[]>();
    for (const event of result.events) {
      const key = `${event.sourceIp ?? "unknown"}>${event.destinationIp ?? "unknown"}`;
      grouped.set(key, [...(grouped.get(key) ?? []), event]);
    }

    return [...grouped.values()]
      .map((events) => toBeaconingFinding(events))
      .filter((finding): finding is BeaconingFinding => finding !== null);
  }
}

function toBeaconingFinding(events: ZeekEvent[]): BeaconingFinding | null {
  if (events.length < 4) {
    return null;
  }

  const sorted = [...events].sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp));
  const intervals = sorted
    .slice(1)
    .map((event, index) => (Date.parse(event.timestamp) - Date.parse(sorted[index]?.timestamp ?? event.timestamp)) / 1000)
    .filter((interval) => Number.isFinite(interval) && interval > 0);

  if (intervals.length < 3) {
    return null;
  }

  const average = intervals.reduce((sum, value) => sum + value, 0) / intervals.length;
  const variance = intervals.reduce((sum, value) => sum + (value - average) ** 2, 0) / intervals.length;
  const jitterRatio = Math.sqrt(variance) / average;

  if (jitterRatio > 0.3) {
    return null;
  }

  const first = sorted[0];
  return {
    sourceIp: first?.sourceIp,
    destinationIp: first?.destinationIp,
    eventCount: sorted.length,
    averageIntervalSeconds: Math.round(average),
    jitterRatio: Number(jitterRatio.toFixed(3)),
    confidence: jitterRatio < 0.1 ? "high" : "medium",
  };
}
