import type { ToolCaller } from "../application/ports.js";
import type {
  AgentAnswer,
  CorrelationResult,
  HealthStatus,
  IncidentSummary,
  IndicatorContext,
  MitreMapping,
  MitreTechnique,
  NormalizedAlert,
  ReasonedIncident,
  ResponseEnvelope,
  TimeRange,
} from "../domain/models.js";
import { isSuccessEnvelope } from "../domain/response.js";

export class SocAgent {
  public constructor(private readonly tools: ToolCaller) {}

  public refuseDestructiveRequest(request: string): AgentAnswer {
    return {
      mode: "refusal",
      title: "Destructive response actions are disabled in version 1",
      evidence: [],
      analysis: [`Request refused: ${request}`],
      recommendations: [
        "Use the MCP server to gather evidence first.",
        "Prepare manual response steps for human approval outside V1 automation.",
      ],
      limitations: ["Version 1 is read-only and cannot block IPs, restart services, or modify firewall rules."],
    };
  }

  public async health(): Promise<AgentAnswer> {
    const health = await this.tools.callTool<HealthStatus>("health_check", {});
    if (!isSuccessEnvelope(health)) {
      return failureAnswer("Health check failed", health);
    }
    return {
      mode: "triage",
      title: `Unified SOC MCP health: ${health.data.status}`,
      evidence: health.data.dependencies.map((dependency) => `${dependency.name}: ${dependency.status}`),
      analysis: [health.data.ok ? "All dependencies are healthy." : "One or more dependencies are unavailable."],
      recommendations: health.data.ok ? [] : ["Review MCP server environment variables and Wazuh connectivity."],
      limitations: [],
      data: health.data,
    };
  }

  public async triageHighSeverity(input: { timeRange?: TimeRange; limit?: number } = {}): Promise<AgentAnswer> {
    const alerts = await this.tools.callTool<NormalizedAlert[]>("wazuh_get_high_severity_alerts", input);
    if (!isSuccessEnvelope(alerts)) {
      return failureAnswer("High-severity alert triage failed", alerts);
    }

    const grouped = groupAlerts(alerts.data);
    return {
      mode: "triage",
      title: `High-severity alert triage (${alerts.data.length} alerts)`,
      severity: alerts.data.some((alert) => alert.severity === "critical") ? "critical" : alerts.data.length > 0 ? "high" : "unknown",
      evidence: alerts.data.map((alert) => summarizeAlert(alert)),
      analysis: grouped,
      recommendations: [
        "Investigate the highest severity alert IDs first.",
        "Correlate suspicious source or destination IPs before recommending response actions.",
      ],
      limitations: alerts.meta.partialFailures?.map((failure) => `${failure.source}: ${failure.message}`) ?? [],
      data: alerts.data,
    };
  }

  public async investigateAlert(alertId: string): Promise<AgentAnswer> {
    const [alert, mitre, correlation, summary] = await Promise.all([
      this.tools.callTool<NormalizedAlert>("wazuh_get_alert_by_id", { alertId }),
      this.tools.callTool<MitreMapping>("mitre_map_alert", { alertId }),
      this.tools.callTool<CorrelationResult>("correlate_alert_context", { alertId, windowMinutes: 30 }),
      this.tools.callTool<IncidentSummary>("summarize_incident", { alertIds: [alertId] }),
    ]);

    const limitations = collectLimitations(alert, mitre, correlation, summary);
    if (!isSuccessEnvelope(alert)) {
      return failureAnswer("Alert investigation failed", alert);
    }

    return {
      mode: "alert_investigation",
      title: `Alert investigation: ${alert.data.id}`,
      severity: alert.data.severity,
      evidence: [
        summarizeAlert(alert.data),
        ...(isSuccessEnvelope(correlation) ? correlation.data.timeline.map((event) => `${event.timestamp} ${event.source}: ${event.title}`) : []),
      ],
      analysis: [
        isSuccessEnvelope(mitre)
          ? `MITRE mapping confidence is ${mitre.data.confidence}: ${mitre.data.reason}`
          : "MITRE mapping was unavailable.",
        isSuccessEnvelope(summary) ? `Incident status: ${summary.data.status}` : "Incident summary was unavailable.",
      ],
      recommendations: isSuccessEnvelope(summary)
        ? summary.data.recommendedNextSteps
        : ["Collect related evidence and validate whether the alert is expected activity."],
      limitations,
      data: {
        alert: alert.data,
        mitre: isSuccessEnvelope(mitre) ? mitre.data : undefined,
        correlation: isSuccessEnvelope(correlation) ? correlation.data : undefined,
        summary: isSuccessEnvelope(summary) ? summary.data : undefined,
      },
    };
  }

  public async investigateIp(ip: string, timeRange?: TimeRange): Promise<AgentAnswer> {
    const [enrichment, correlation] = await Promise.all([
      this.tools.callTool<IndicatorContext>("enrich_indicator", { type: "ip", value: ip }),
      this.tools.callTool<CorrelationResult>("correlate_ip_activity", { ip, timeRange }),
    ]);

    if (!isSuccessEnvelope(correlation)) {
      return failureAnswer("IP investigation failed", correlation);
    }

    return {
      mode: "ip_investigation",
      title: `IP investigation: ${ip}`,
      severity: correlation.data.findings.some((finding) => finding.severity === "critical")
        ? "critical"
        : correlation.data.findings.some((finding) => finding.severity === "high")
          ? "high"
          : "unknown",
      evidence: correlation.data.timeline.map((event) => `${event.timestamp} ${event.source}: ${event.title}`),
      analysis: [
        isSuccessEnvelope(enrichment)
          ? `Indicator classification: ${enrichment.data.classification}`
          : "Indicator enrichment was unavailable.",
        ...correlation.data.findings.map((finding) => `${finding.title}: ${finding.rationale}`),
      ],
      recommendations: [
        "Confirm source and destination roles before containment decisions.",
        "Review related alerts and network events with the affected asset owner.",
      ],
      limitations: [
        ...(enrichment.success ? enrichment.meta.partialFailures?.map((failure) => failure.message) ?? [] : [enrichment.error.message]),
        ...(correlation.meta.partialFailures?.map((failure) => `${failure.source}: ${failure.message}`) ?? []),
      ],
      data: {
        enrichment: isSuccessEnvelope(enrichment) ? enrichment.data : undefined,
        correlation: correlation.data,
      },
    };
  }

  public async explainTechnique(techniqueId: string): Promise<AgentAnswer> {
    const technique = await this.tools.callTool<MitreTechnique>("mitre_get_technique", { techniqueId });
    if (!isSuccessEnvelope(technique)) {
      return failureAnswer("MITRE technique lookup failed", technique);
    }
    return {
      mode: "mitre_explanation",
      title: `${technique.data.id}: ${technique.data.name}`,
      evidence: [`Tactic: ${technique.data.tactic}`, technique.data.url],
      analysis: [technique.data.description],
      recommendations: ["Use alert-specific evidence before deciding whether this technique applies to an incident."],
      limitations: ["Technique metadata is from the local V1 catalog, not a live ATT&CK data sync."],
      data: technique.data,
    };
  }

  public async summarizeIncident(input: { alertIds?: string[]; entityIp?: string; timeRange?: TimeRange }): Promise<AgentAnswer> {
    const reasoned = await this.tools.callTool<ReasonedIncident>("reason_about_incident", input);
    if (!isSuccessEnvelope(reasoned)) {
      return failureAnswer("Incident summary failed", reasoned);
    }
    const summary = reasoned.data.incident;
    const reasoning = reasoned.data.reasoning;
    return {
      mode: "incident_report",
      title: summary.title,
      severity: summary.severity,
      evidence: summary.evidence.map((entry) => `${entry.source}:${entry.id} ${entry.summary}`),
      analysis: [`Status: ${summary.status}`, `Confidence: ${reasoning.confidence}`, ...reasoning.analysis],
      recommendations: reasoning.recommendations,
      limitations: reasoning.limitations,
      data: reasoned.data,
    };
  }
}

function failureAnswer(title: string, envelope: ResponseEnvelope<unknown>): AgentAnswer {
  return {
    mode: "clarification",
    title,
    evidence: [],
    analysis: envelope.success ? ["No failure was reported."] : [envelope.error.message],
    recommendations: ["Check the requested scope, time range, and MCP server dependency health."],
    limitations: envelope.success ? [] : [`${envelope.error.code}: ${envelope.error.message}`],
  };
}

function collectLimitations(...envelopes: ResponseEnvelope<unknown>[]): string[] {
  return envelopes.flatMap((envelope) => {
    if (envelope.success) {
      return envelope.meta.partialFailures?.map((failure) => `${failure.source}: ${failure.message}`) ?? [];
    }
    return [`${envelope.error.code}: ${envelope.error.message}`];
  });
}

function summarizeAlert(alert: NormalizedAlert): string {
  return `${alert.id} ${alert.severity.toUpperCase()} rule=${alert.rule?.id ?? "unknown"} agent=${alert.agent?.name ?? alert.agent?.id ?? "unknown"} ${alert.rule?.description ?? ""}`.trim();
}

function groupAlerts(alerts: NormalizedAlert[]): string[] {
  const byAgent = new Map<string, number>();
  const byRule = new Map<string, number>();
  for (const alert of alerts) {
    const agent = alert.agent?.name ?? alert.agent?.id ?? "unknown";
    const rule = alert.rule?.id ?? "unknown";
    byAgent.set(agent, (byAgent.get(agent) ?? 0) + 1);
    byRule.set(rule, (byRule.get(rule) ?? 0) + 1);
  }
  return [
    `Agents involved: ${[...byAgent.entries()].map(([key, count]) => `${key} (${count})`).join(", ") || "none"}`,
    `Rules involved: ${[...byRule.entries()].map(([key, count]) => `${key} (${count})`).join(", ") || "none"}`,
  ];
}
