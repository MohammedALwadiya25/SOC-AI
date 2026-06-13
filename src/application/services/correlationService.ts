import type { SourceFailure, CorrelationFinding, CorrelationResult, IncidentSummary, MitreMapping, NormalizedAlert, TimeRange, TimelineEvent } from "../../domain/models.js";
import { AppError, toSafeError } from "../../domain/errors.js";
import { alertToTimeline, suricataToTimeline, zeekToTimeline } from "../normalizers.js";
import type { AlertService } from "./alertService.js";
import type { MitreService } from "./mitreService.js";
import type { SuricataService } from "./suricataService.js";
import type { ZeekService } from "./zeekService.js";
import { defaultTimeRange, expandAround, compareIsoAsc } from "../../utils/time.js";
import { effectiveLimit, type ServiceContext } from "./context.js";

export class CorrelationService {
  public constructor(
    private readonly alerts: AlertService,
    private readonly zeek: ZeekService,
    private readonly suricata: SuricataService,
    private readonly mitre: MitreService,
    private readonly context: ServiceContext,
  ) {}

  public async correlateIpActivity(input: { ip: string; timeRange?: TimeRange; limit?: number }): Promise<{
    result: CorrelationResult;
    partialFailures: SourceFailure[];
  }> {
    const timeRange = input.timeRange ?? defaultTimeRange(this.context.config.defaultTimeRangeHours);
    const limit = effectiveLimit(input.limit, this.context);
    const failures: SourceFailure[] = [];

    const [alertResult, zeekResult, suricataResult] = await Promise.all([
      captureSource("wazuh", () => this.alerts.searchAlerts({ ip: input.ip, timeRange, limit })),
      captureSource("zeek", () => this.zeek.searchLogs({ filters: { sourceIp: input.ip, destinationIp: input.ip }, timeRange, limit })),
      captureSource("suricata", () => this.suricata.getAlerts({ filters: { sourceIp: input.ip }, timeRange, limit })),
    ]);

    if (!alertResult.success) failures.push(alertResult.failure);
    if (!zeekResult.success) failures.push(zeekResult.failure);
    if (!suricataResult.success) failures.push(suricataResult.failure);

    const alertData = alertResult.success ? alertResult.value.alerts : [];
    const zeekData = zeekResult.success ? zeekResult.value.events : [];
    const suricataData = suricataResult.success ? suricataResult.value.alerts : [];

    const timeline = [
      ...alertData.map(alertToTimeline),
      ...zeekData.map(zeekToTimeline),
      ...suricataData.map(suricataToTimeline),
    ].sort((left, right) => compareIsoAsc(left.timestamp, right.timestamp));

    return {
      partialFailures: failures,
      result: {
        entity: input.ip,
        timeRange,
        timeline,
        findings: buildFindings(alertData, timeline),
        evidenceCounts: {
          wazuh: alertData.length,
          zeek: zeekData.length,
          suricata: suricataData.length,
        },
      },
    };
  }

  public async correlateAlertContext(input: { alertId: string; windowMinutes: number; limit?: number }): Promise<{
    result: CorrelationResult;
    partialFailures: SourceFailure[];
  }> {
    const alert = await this.alerts.getAlertById(input.alertId);
    const ip = alert.network?.sourceIp ?? alert.network?.destinationIp ?? alert.agent?.ip;
    if (!ip) {
      const timeRange = expandAround(alert.timestamp, input.windowMinutes);
      return {
        partialFailures: [],
        result: {
          entity: alert.id,
          timeRange,
          timeline: [alertToTimeline(alert)],
          findings: [
            {
              title: "Alert has limited network context",
              severity: alert.severity,
              confidence: "medium",
              evidenceCount: 1,
              rationale: "No source, destination, or agent IP was present in the normalized alert.",
            },
          ],
          evidenceCounts: { wazuh: 1, zeek: 0, suricata: 0 },
        },
      };
    }

    const correlated = await this.correlateIpActivity({
      ip,
      timeRange: expandAround(alert.timestamp, input.windowMinutes),
      limit: input.limit,
    });
    correlated.result.entity = alert.id;
    correlated.result.timeline = [alertToTimeline(alert), ...correlated.result.timeline]
      .filter((event, index, array) => array.findIndex((candidate) => candidate.evidenceId === event.evidenceId) === index)
      .sort((left, right) => compareIsoAsc(left.timestamp, right.timestamp));
    return correlated;
  }

  public async summarizeIncident(input: { alertIds?: string[]; entityIp?: string; timeRange?: TimeRange; limit?: number }): Promise<{
    summary: IncidentSummary;
    partialFailures: SourceFailure[];
  }> {
    const failures: SourceFailure[] = [];
    const alertIds = input.alertIds ?? [];
    const alerts = await Promise.all(alertIds.map((alertId) => captureSource("wazuh", () => this.alerts.getAlertById(alertId))));
    for (const result of alerts) {
      if (!result.success) failures.push(result.failure);
    }
    const alertData = alerts.flatMap((result) => (result.success ? [result.value] : []));

    const correlation = input.entityIp
      ? await this.correlateIpActivity({
          ip: input.entityIp,
          timeRange: input.timeRange,
          limit: input.limit,
        })
      : alertData[0]
        ? await this.correlateAlertContext({
            alertId: alertData[0].id,
            windowMinutes: 30,
            limit: input.limit,
          })
        : null;

    if (correlation) {
      failures.push(...correlation.partialFailures);
    }

    const mappings = await Promise.all(alertData.map((alert) => captureSource("mitre", () => this.mitre.mapAlert({ alert }))));
    for (const result of mappings) {
      if (!result.success) failures.push(result.failure);
    }
    const mitreMappings = mappings.flatMap((result) => (result.success ? [result.value] : []));

    const timeline = correlation?.result.timeline ?? alertData.map(alertToTimeline);
    return {
      partialFailures: failures,
      summary: {
        title: buildIncidentTitle(alertData, input.entityIp),
        severity: highestSeverity(timeline),
        status: timeline.length > 0 ? "triaged" : "insufficient_evidence",
        affectedAssets: uniqueStrings(
          alertData.flatMap((alert) => [alert.agent?.name, alert.agent?.ip, alert.network?.sourceIp, alert.network?.destinationIp]),
        ),
        timeline,
        evidence: timeline.map((event) => ({
          source: event.source,
          id: event.evidenceId ?? "unknown",
          summary: event.title,
        })),
        mitre: mitreMappings,
        confidence: timeline.length >= 3 ? "medium" : "low",
        recommendedNextSteps: [
          "Review affected asset ownership and recent authentication activity.",
          "Confirm whether the observed network activity is expected for the host role.",
          "Preserve related Wazuh, Zeek, and Suricata evidence before taking response action.",
        ],
        limitations: failures.length > 0 ? failures.map((failure) => `${failure.source}: ${failure.message}`) : [],
      },
    };
  }
}

type Captured<TValue> =
  | {
      success: true;
      value: TValue;
    }
  | {
      success: false;
      failure: SourceFailure;
    };

async function captureSource<TValue>(source: string, operation: () => Promise<TValue>): Promise<Captured<TValue>> {
  try {
    return {
      success: true,
      value: await operation(),
    };
  } catch (error) {
    const safe = toSafeError(error);
    return {
      success: false,
      failure: {
        source,
        code: safe.code,
        message: safe.message,
      },
    };
  }
}

function buildFindings(alerts: NormalizedAlert[], timeline: TimelineEvent[]): CorrelationFinding[] {
  const highAlerts = alerts.filter((alert) => alert.severity === "high" || alert.severity === "critical");
  const findings: CorrelationFinding[] = [];

  if (highAlerts.length > 0) {
    findings.push({
      title: "High-severity Wazuh alerts observed",
      severity: highAlerts.some((alert) => alert.severity === "critical") ? "critical" : "high",
      confidence: "high",
      evidenceCount: highAlerts.length,
      rationale: "One or more high/critical Wazuh alerts matched the correlated entity.",
    });
  }

  if (timeline.length >= 5) {
    findings.push({
      title: "Multiple related events in time window",
      severity: "medium",
      confidence: "medium",
      evidenceCount: timeline.length,
      rationale: "The entity appears across multiple normalized evidence records.",
    });
  }

  return findings;
}

function buildIncidentTitle(alerts: NormalizedAlert[], entityIp?: string): string {
  const firstRule = alerts[0]?.rule?.description;
  if (firstRule) {
    return `Incident summary: ${firstRule}`;
  }
  if (entityIp) {
    return `Incident summary for ${entityIp}`;
  }
  return "Incident summary";
}

function highestSeverity(timeline: TimelineEvent[]): IncidentSummary["severity"] {
  const order: IncidentSummary["severity"][] = ["unknown", "low", "medium", "high", "critical"];
  return timeline.reduce<IncidentSummary["severity"]>((highest, event) => {
    return order.indexOf(event.severity) > order.indexOf(highest) ? event.severity : highest;
  }, "unknown");
}

function uniqueStrings(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))];
}
