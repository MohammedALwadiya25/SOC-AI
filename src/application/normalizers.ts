import type {
  MitreTechniqueRef,
  NormalizedAlert,
  SeverityLabel,
  SuricataAlert,
  TimelineEvent,
  ZeekEvent,
} from "../domain/models.js";
import { asNumber, asString, asStringArray, firstDefined, getPath, pickDefined } from "../utils/records.js";

export function severityFromScore(score: number | undefined): SeverityLabel {
  if (score === undefined) {
    return "unknown";
  }
  if (score >= 13) {
    return "critical";
  }
  if (score >= 10) {
    return "high";
  }
  if (score >= 5) {
    return "medium";
  }
  return "low";
}

export function normalizeAlert(id: string, source: Record<string, unknown>): NormalizedAlert {
  const timestamp = asString(firstDefined(source["@timestamp"], source.timestamp)) ?? new Date(0).toISOString();
  const ruleLevel = asNumber(getPath(source, ["rule", "level"]));
  const mitreIds = asStringArray(getPath(source, ["rule", "mitre", "id"])) ?? [];
  const mitreTactics = asStringArray(getPath(source, ["rule", "mitre", "tactic"])) ?? [];
  const mitreTechniques = asStringArray(getPath(source, ["rule", "mitre", "technique"])) ?? [];
  const sourceIp = asString(
    firstDefined(
      getPath(source, ["data", "srcip"]),
      getPath(source, ["data", "src_ip"]),
      getPath(source, ["source", "ip"]),
    ),
  );
  const destinationIp = asString(
    firstDefined(
      getPath(source, ["data", "dstip"]),
      getPath(source, ["data", "dest_ip"]),
      getPath(source, ["data", "dst_ip"]),
      getPath(source, ["destination", "ip"]),
    ),
  );

  return {
    id,
    timestamp,
    severity: severityFromScore(ruleLevel),
    severityScore: ruleLevel ?? 0,
    source: inferAlertSource(source),
    agent: pickDefined({
      id: asString(getPath(source, ["agent", "id"])),
      name: asString(getPath(source, ["agent", "name"])),
      ip: asString(getPath(source, ["agent", "ip"])),
    }),
    rule: pickDefined({
      id: asString(getPath(source, ["rule", "id"])),
      level: ruleLevel,
      description: asString(getPath(source, ["rule", "description"])),
      groups: asStringArray(getPath(source, ["rule", "groups"])),
      mitre: mitreIds.map((techniqueId, index): MitreTechniqueRef => ({
        id: techniqueId,
        name: mitreTechniques[index],
        tactic: mitreTactics[index] ?? mitreTactics[0],
      })),
    }),
    network: pickDefined({
      sourceIp,
      sourcePort: asNumber(firstDefined(getPath(source, ["data", "srcport"]), getPath(source, ["data", "src_port"]))),
      destinationIp,
      destinationPort: asNumber(
        firstDefined(
          getPath(source, ["data", "dstport"]),
          getPath(source, ["data", "dest_port"]),
          getPath(source, ["data", "dst_port"]),
        ),
      ),
      protocol: asString(firstDefined(getPath(source, ["data", "protocol"]), getPath(source, ["network", "protocol"]))),
    }),
    message: asString(getPath(source, ["rule", "description"])),
    normalizedFields: pickDefined({
      decoder: asString(getPath(source, ["decoder", "name"])),
      manager: asString(getPath(source, ["manager", "name"])),
      location: asString(source.location),
    }),
  };
}

export function normalizeZeekEvent(id: string, source: Record<string, unknown>): ZeekEvent {
  const timestamp = asString(firstDefined(source["@timestamp"], source.timestamp)) ?? new Date(0).toISOString();
  const logType = inferZeekLogType(source);
  const answers = asStringArray(firstDefined(getPath(source, ["data", "answers"]), getPath(source, ["data", "zeek", "answers"])));

  return {
    id,
    timestamp,
    logType,
    sourceIp: asString(firstDefined(getPath(source, ["data", "id.orig_h"]), getPath(source, ["data", "srcip"]))),
    sourcePort: asNumber(firstDefined(getPath(source, ["data", "id.orig_p"]), getPath(source, ["data", "src_port"]))),
    destinationIp: asString(firstDefined(getPath(source, ["data", "id.resp_h"]), getPath(source, ["data", "dstip"]))),
    destinationPort: asNumber(firstDefined(getPath(source, ["data", "id.resp_p"]), getPath(source, ["data", "dst_port"]))),
    protocol: asString(firstDefined(getPath(source, ["data", "proto"]), getPath(source, ["network", "protocol"]))),
    service: asString(getPath(source, ["data", "service"])),
    query: asString(getPath(source, ["data", "query"])),
    answer: answers?.join(","),
    action: asString(getPath(source, ["data", "connection_state"])),
    durationMs: secondsToMs(asNumber(getPath(source, ["data", "duration"]))),
    bytesIn: asNumber(getPath(source, ["data", "orig_bytes"])),
    bytesOut: asNumber(getPath(source, ["data", "resp_bytes"])),
    normalizedFields: pickDefined({
      uid: asString(getPath(source, ["data", "uid"])),
      decoder: asString(getPath(source, ["decoder", "name"])),
    }),
  };
}

export function normalizeSuricataAlert(id: string, source: Record<string, unknown>): SuricataAlert {
  const timestamp = asString(firstDefined(source["@timestamp"], source.timestamp)) ?? new Date(0).toISOString();
  return {
    id,
    timestamp,
    signature: asString(getPath(source, ["data", "alert", "signature"])),
    signatureId: asString(getPath(source, ["data", "alert", "signature_id"])),
    category: asString(getPath(source, ["data", "alert", "category"])),
    severity: asNumber(getPath(source, ["data", "alert", "severity"])),
    sourceIp: asString(firstDefined(getPath(source, ["data", "src_ip"]), getPath(source, ["data", "srcip"]))),
    sourcePort: asNumber(firstDefined(getPath(source, ["data", "src_port"]), getPath(source, ["data", "srcport"]))),
    destinationIp: asString(firstDefined(getPath(source, ["data", "dest_ip"]), getPath(source, ["data", "dst_ip"]))),
    destinationPort: asNumber(firstDefined(getPath(source, ["data", "dest_port"]), getPath(source, ["data", "dstport"]))),
    protocol: asString(getPath(source, ["data", "proto"])),
    action: asString(getPath(source, ["data", "alert", "action"])),
    normalizedFields: pickDefined({
      eventType: asString(getPath(source, ["data", "event_type"])),
      flowId: asString(getPath(source, ["data", "flow_id"])),
      decoder: asString(getPath(source, ["decoder", "name"])),
    }),
  };
}

export function alertToTimeline(alert: NormalizedAlert): TimelineEvent {
  return {
    timestamp: alert.timestamp,
    source: "wazuh",
    title: alert.rule?.description ?? "Wazuh alert",
    severity: alert.severity,
    entity: alert.agent?.name ?? alert.network?.sourceIp ?? alert.network?.destinationIp,
    evidenceId: alert.id,
    details: pickDefined({
      ruleId: alert.rule?.id,
      ruleLevel: alert.rule?.level,
      sourceIp: alert.network?.sourceIp,
      destinationIp: alert.network?.destinationIp,
    }),
  };
}

export function zeekToTimeline(event: ZeekEvent): TimelineEvent {
  return {
    timestamp: event.timestamp,
    source: "zeek",
    title: `Zeek ${event.logType} event`,
    severity: "unknown",
    entity: event.sourceIp ?? event.destinationIp,
    evidenceId: event.id,
    details: pickDefined({
      sourceIp: event.sourceIp,
      destinationIp: event.destinationIp,
      service: event.service,
      query: event.query,
      answer: event.answer,
    }),
  };
}

export function suricataToTimeline(alert: SuricataAlert): TimelineEvent {
  return {
    timestamp: alert.timestamp,
    source: "suricata",
    title: alert.signature ?? "Suricata alert",
    severity: severityFromScore(alert.severity),
    entity: alert.sourceIp ?? alert.destinationIp,
    evidenceId: alert.id,
    details: pickDefined({
      signatureId: alert.signatureId,
      category: alert.category,
      sourceIp: alert.sourceIp,
      destinationIp: alert.destinationIp,
    }),
  };
}

function inferAlertSource(source: Record<string, unknown>): NormalizedAlert["source"] {
  const groups = asStringArray(getPath(source, ["rule", "groups"]))?.join(" ").toLowerCase() ?? "";
  const decoder = asString(getPath(source, ["decoder", "name"]))?.toLowerCase() ?? "";
  const eventType = asString(getPath(source, ["data", "event_type"]))?.toLowerCase() ?? "";
  if (groups.includes("suricata") || decoder.includes("suricata") || eventType === "alert") {
    return "suricata";
  }
  if (groups.includes("zeek") || decoder.includes("zeek") || decoder.includes("bro")) {
    return "zeek";
  }
  if (groups.includes("pfsense") || decoder.includes("pfsense")) {
    return "pfsense";
  }
  return "wazuh";
}

function inferZeekLogType(source: Record<string, unknown>): ZeekEvent["logType"] {
  const groups = asStringArray(getPath(source, ["rule", "groups"]))?.join(" ").toLowerCase() ?? "";
  const decoder = asString(getPath(source, ["decoder", "name"]))?.toLowerCase() ?? "";
  const raw = `${groups} ${decoder}`;
  if (raw.includes("dns")) {
    return "dns";
  }
  if (raw.includes("conn")) {
    return "conn";
  }
  if (raw.includes("http")) {
    return "http";
  }
  if (raw.includes("ssl") || raw.includes("tls")) {
    return "ssl";
  }
  if (raw.includes("notice")) {
    return "notice";
  }
  if (raw.includes("files")) {
    return "files";
  }
  return "unknown";
}

function secondsToMs(value: number | undefined): number | undefined {
  return value === undefined ? undefined : Math.round(value * 1000);
}
