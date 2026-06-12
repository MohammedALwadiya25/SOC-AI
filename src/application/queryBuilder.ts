import type { TimeRange } from "../domain/models.js";

type Clause = Record<string, unknown>;

export interface FilterClause {
  field: string;
  value: string | number | boolean;
  operator?: "term" | "match" | "range_gte";
}

export interface SearchBuildInput {
  timeRange?: TimeRange;
  limit: number;
  filters?: FilterClause[];
  keyword?: string;
  keywordFields?: string[];
  ip?: string;
  ipFields?: string[];
  ids?: string[];
  sourceFields?: string[];
  sortAscending?: boolean;
}

export function buildSearchBody(input: SearchBuildInput): Record<string, unknown> {
  const filter: Clause[] = [];
  const must: Clause[] = [];

  if (input.timeRange) {
    filter.push({
      range: {
        "@timestamp": {
          gte: input.timeRange.start,
          lte: input.timeRange.end,
        },
      },
    });
  }

  for (const filterClause of input.filters ?? []) {
    if (filterClause.operator === "range_gte") {
      filter.push({
        range: {
          [filterClause.field]: {
            gte: filterClause.value,
          },
        },
      });
      continue;
    }
    if (filterClause.operator === "match") {
      must.push({
        match: {
          [filterClause.field]: filterClause.value,
        },
      });
      continue;
    }
    filter.push({
      term: {
        [filterClause.field]: filterClause.value,
      },
    });
  }

  if (input.keyword && input.keywordFields && input.keywordFields.length > 0) {
    must.push({
      multi_match: {
        query: input.keyword,
        fields: input.keywordFields,
        type: "best_fields",
        operator: "and",
      },
    });
  }

  if (input.ip && input.ipFields && input.ipFields.length > 0) {
    filter.push({
      bool: {
        should: input.ipFields.map((field) => ({
          term: {
            [field]: input.ip,
          },
        })),
        minimum_should_match: 1,
      },
    });
  }

  if (input.ids && input.ids.length > 0) {
    filter.push({
      ids: {
        values: input.ids,
      },
    });
  }

  const body: Record<string, unknown> = {
    size: input.limit,
    track_total_hits: true,
    query: {
      bool: {
        filter,
        must,
      },
    },
    sort: [
      {
        "@timestamp": {
          order: input.sortAscending ? "asc" : "desc",
        },
      },
    ],
  };

  if (input.sourceFields) {
    body._source = input.sourceFields;
  }

  return body;
}

export const ALERT_SOURCE_FIELDS = [
  "@timestamp",
  "timestamp",
  "agent",
  "rule",
  "decoder",
  "manager",
  "location",
  "data.srcip",
  "data.src_ip",
  "data.dstip",
  "data.dest_ip",
  "data.dst_ip",
  "data.srcport",
  "data.src_port",
  "data.dstport",
  "data.dest_port",
  "data.dst_port",
  "data.protocol",
  "source.ip",
  "destination.ip",
  "network.protocol",
  "full_log",
] as const;

export const ALERT_KEYWORD_FIELDS = [
  "rule.description",
  "rule.groups",
  "agent.name",
  "decoder.name",
  "location",
] as const;

export const ALERT_IP_FIELDS = [
  "data.srcip",
  "data.src_ip",
  "source.ip",
  "data.dstip",
  "data.dest_ip",
  "data.dst_ip",
  "destination.ip",
] as const;

export const ZEEK_SOURCE_FIELDS = [
  "@timestamp",
  "timestamp",
  "data.zeek",
  "data.uid",
  "data.srcip",
  "data.src_port",
  "data.dstip",
  "data.dst_port",
  "data.protocol",
  "data.service",
  "data.query",
  "data.answers",
  "data.duration",
  "data.orig_bytes",
  "data.resp_bytes",
  "decoder.name",
  "rule.groups",
] as const;

export const ZEEK_IP_FIELDS = [
  "data.srcip",
  "data.id.orig_h",
  "source.ip",
  "data.dstip",
  "data.id.resp_h",
  "destination.ip",
] as const;

export const SURICATA_SOURCE_FIELDS = [
  "@timestamp",
  "timestamp",
  "data.alert",
  "data.event_type",
  "data.src_ip",
  "data.srcip",
  "data.src_port",
  "data.dest_ip",
  "data.dst_ip",
  "data.dest_port",
  "data.proto",
  "data.flow",
  "decoder.name",
  "rule.groups",
] as const;

export const SURICATA_IP_FIELDS = [
  "data.src_ip",
  "data.srcip",
  "source.ip",
  "data.dest_ip",
  "data.dst_ip",
  "destination.ip",
] as const;
