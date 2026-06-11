import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import type { AppServices } from "../infrastructure/container.js";
import type { Logger } from "../application/ports.js";
import type { ResponseEnvelope, ResponseMeta } from "../domain/models.js";
import { errorEnvelope, successEnvelope } from "../domain/response.js";
import { toSafeError } from "../domain/errors.js";
import {
  agentByIdInputSchema,
  agentListInputSchema,
  alertByIdInputSchema,
  alertListInputSchema,
  alertSearchInputSchema,
  correlateAlertInputSchema,
  correlateIpInputSchema,
  emptyInputSchema,
  enrichIndicatorInputSchema,
  highSeverityInputSchema,
  mitreCoverageInputSchema,
  mitreMapAlertInputSchema,
  mitreTechniqueInputSchema,
  publicInputSchema,
  reasonIncidentInputSchema,
  summarizeIncidentInputSchema,
  suricataSearchInputSchema,
  timelineInputSchema,
  topNInputSchema,
  zeekBeaconingInputSchema,
  zeekSearchInputSchema,
} from "./schemas.js";

interface ToolSuccess<TData> {
  data: TData;
  meta?: Omit<ResponseMeta, "timestamp" | "tool" | "durationMs">;
}

interface ToolDefinition {
  name: string;
  description: string;
  inputKeys: readonly string[];
  inputSchema: z.ZodType<unknown>;
  handler(input: unknown): Promise<ToolSuccess<unknown>>;
}

export function registerSocTools(server: McpServer, services: AppServices, logger: Logger): void {
  for (const definition of buildToolDefinitions(services)) {
    server.registerTool(
      definition.name,
      {
        description: definition.description,
        inputSchema: publicInputSchema(definition.inputKeys),
      },
      async (args) => {
        const envelope = await executeTool(definition, args ?? {}, logger);
        return {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify(envelope),
            },
          ],
          structuredContent: envelope as unknown as Record<string, unknown>,
        };
      },
    );
  }
}

export async function executeTool(
  definition: ToolDefinition,
  rawInput: unknown,
  logger: Logger,
): Promise<ResponseEnvelope<unknown>> {
  const startedAt = Date.now();
  try {
    const input = await definition.inputSchema.parseAsync(rawInput);
    const result = await definition.handler(input);
    const durationMs = Date.now() - startedAt;
    logger.info({ tool: definition.name, durationMs, success: true }, "tool completed");
    return successEnvelope(result.data, {
      ...result.meta,
      tool: definition.name,
      durationMs,
    });
  } catch (error) {
    const durationMs = Date.now() - startedAt;
    const safeError = toSafeError(error);
    logger.warn(
      {
        tool: definition.name,
        durationMs,
        success: false,
        errorCode: safeError.code,
      },
      "tool failed",
    );
    return errorEnvelope(safeError, {
      tool: definition.name,
      durationMs,
    });
  }
}

function defineTool<TInput, TData>(definition: {
  name: string;
  description: string;
  inputKeys: readonly string[];
  inputSchema: z.ZodType<TInput>;
  handler(input: TInput): Promise<ToolSuccess<TData>>;
}): ToolDefinition {
  return {
    ...definition,
    inputSchema: definition.inputSchema as z.ZodType<unknown>,
    handler: async (input: unknown) => definition.handler(input as TInput),
  };
}

export function buildToolDefinitions(services: AppServices): ToolDefinition[] {
  return [
    defineTool({
      name: "health_check",
      description: "Check MCP server, Wazuh API, and Wazuh Indexer connectivity.",
      inputKeys: [],
      inputSchema: emptyInputSchema,
      handler: async () => ({ data: await services.health.check() }),
    }),
    defineTool({
      name: "wazuh_get_alerts",
      description: "Return recent normalized Wazuh alerts.",
      inputKeys: ["timeRange", "limit"],
      inputSchema: alertListInputSchema,
      handler: async (input) => {
        const result = await services.alerts.getAlerts(input);
        return {
          data: result.alerts,
          meta: {
            pagination: {
              limit: input.limit ?? result.alerts.length,
              returned: result.alerts.length,
              hasMore: result.total > result.alerts.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "wazuh_search_alerts",
      description: "Search normalized Wazuh alerts by keyword, severity, agent, rule, or IP.",
      inputKeys: ["timeRange", "limit", "keyword", "severityMin", "agentId", "ruleId", "ip"],
      inputSchema: alertSearchInputSchema,
      handler: async (input) => {
        const result = await services.alerts.searchAlerts(input);
        return {
          data: result.alerts,
          meta: {
            pagination: {
              limit: input.limit ?? result.alerts.length,
              returned: result.alerts.length,
              hasMore: result.total > result.alerts.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "wazuh_get_alert_by_id",
      description: "Return one normalized Wazuh alert by ID.",
      inputKeys: ["alertId"],
      inputSchema: alertByIdInputSchema,
      handler: async (input) => ({ data: await services.alerts.getAlertById(input.alertId) }),
    }),
    defineTool({
      name: "wazuh_get_high_severity_alerts",
      description: "Return high and critical Wazuh alerts.",
      inputKeys: ["timeRange", "severityMin", "limit"],
      inputSchema: highSeverityInputSchema,
      handler: async (input) => {
        const result = await services.alerts.getHighSeverityAlerts(input);
        return {
          data: result.alerts,
          meta: {
            pagination: {
              limit: input.limit ?? result.alerts.length,
              returned: result.alerts.length,
              hasMore: result.total > result.alerts.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "wazuh_list_agents",
      description: "List Wazuh agents and health status.",
      inputKeys: ["status", "osPlatform", "limit"],
      inputSchema: agentListInputSchema,
      handler: async (input) => {
        const agents = await services.agents.listAgents(input);
        return {
          data: agents,
          meta: {
            pagination: {
              limit: input.limit ?? agents.length,
              returned: agents.length,
              hasMore: false,
            },
          },
        };
      },
    }),
    defineTool({
      name: "wazuh_get_agent_status",
      description: "Return one Wazuh agent status object.",
      inputKeys: ["agentId"],
      inputSchema: agentByIdInputSchema,
      handler: async (input) => ({ data: await services.agents.getAgentStatus(input.agentId) }),
    }),
    defineTool({
      name: "wazuh_get_agent_summary",
      description: "Return Wazuh agent OS, IP, status, and last-seen summary.",
      inputKeys: ["agentId"],
      inputSchema: agentByIdInputSchema,
      handler: async (input) => ({ data: await services.agents.getAgentSummary(input.agentId) }),
    }),
    defineTool({
      name: "zeek_search_logs",
      description: "Search normalized Zeek events stored in Wazuh Indexer.",
      inputKeys: ["timeRange", "limit", "logType", "filters"],
      inputSchema: zeekSearchInputSchema,
      handler: async (input) => {
        const result = await services.zeek.searchLogs(input);
        return {
          data: result.events,
          meta: {
            pagination: {
              limit: input.limit ?? result.events.length,
              returned: result.events.length,
              hasMore: result.total > result.events.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "zeek_get_dns_activity",
      description: "Return Zeek DNS activity by query, source IP, or answer.",
      inputKeys: ["timeRange", "limit", "filters"],
      inputSchema: zeekSearchInputSchema.omit({ logType: true }),
      handler: async (input) => {
        const result = await services.zeek.getDnsActivity(input);
        return {
          data: result.events,
          meta: {
            pagination: {
              limit: input.limit ?? result.events.length,
              returned: result.events.length,
              hasMore: result.total > result.events.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "zeek_get_connection_activity",
      description: "Return Zeek connection activity by IP, protocol, or service.",
      inputKeys: ["timeRange", "limit", "filters"],
      inputSchema: zeekSearchInputSchema.omit({ logType: true }),
      handler: async (input) => {
        const result = await services.zeek.getConnectionActivity(input);
        return {
          data: result.events,
          meta: {
            pagination: {
              limit: input.limit ?? result.events.length,
              returned: result.events.length,
              hasMore: result.total > result.events.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "zeek_detect_beaconing",
      description: "Detect periodic outbound Zeek connection activity.",
      inputKeys: ["timeRange", "sourceIp", "destinationIp", "limit"],
      inputSchema: zeekBeaconingInputSchema,
      handler: async (input) => ({ data: await services.zeek.detectBeaconing(input) }),
    }),
    defineTool({
      name: "suricata_get_alerts",
      description: "Return normalized Suricata alerts indexed by Wazuh.",
      inputKeys: ["timeRange", "limit", "filters"],
      inputSchema: suricataSearchInputSchema,
      handler: async (input) => {
        const result = await services.suricata.getAlerts(input);
        return {
          data: result.alerts,
          meta: {
            pagination: {
              limit: input.limit ?? result.alerts.length,
              returned: result.alerts.length,
              hasMore: result.total > result.alerts.length,
            },
          },
        };
      },
    }),
    defineTool({
      name: "suricata_get_top_signatures",
      description: "Group Suricata alerts by signature.",
      inputKeys: ["timeRange", "limit"],
      inputSchema: topNInputSchema,
      handler: async (input) => ({ data: await services.suricata.getTopSignatures(input) }),
    }),
    defineTool({
      name: "suricata_get_top_talkers",
      description: "Group Suricata alerts by source and destination IP.",
      inputKeys: ["timeRange", "limit"],
      inputSchema: topNInputSchema,
      handler: async (input) => ({ data: await services.suricata.getTopTalkers(input) }),
    }),
    defineTool({
      name: "suricata_timeline",
      description: "Bucket Suricata alerts over time.",
      inputKeys: ["timeRange", "bucketSizeMinutes", "limit"],
      inputSchema: timelineInputSchema,
      handler: async (input) => ({ data: await services.suricata.timeline(input) }),
    }),
    defineTool({
      name: "mitre_map_alert",
      description: "Map a Wazuh alert or inline normalized alert to MITRE ATT&CK.",
      inputKeys: ["alertId", "alert"],
      inputSchema: mitreMapAlertInputSchema,
      handler: async (input) => ({ data: await services.mitre.mapAlert(input) }),
    }),
    defineTool({
      name: "mitre_get_technique",
      description: "Return MITRE ATT&CK technique metadata from the local V1 catalog.",
      inputKeys: ["techniqueId"],
      inputSchema: mitreTechniqueInputSchema,
      handler: async (input) => ({ data: services.mitre.getTechnique(input.techniqueId) }),
    }),
    defineTool({
      name: "mitre_rule_coverage",
      description: "Analyze Wazuh rule MITRE coverage from recent alerts.",
      inputKeys: ["ruleId", "group", "limit"],
      inputSchema: mitreCoverageInputSchema,
      handler: async (input) => ({ data: await services.mitre.ruleCoverage(input) }),
    }),
    defineTool({
      name: "correlate_ip_activity",
      description: "Correlate Wazuh, Zeek, Suricata, and available indexed activity for one IP.",
      inputKeys: ["ip", "timeRange", "limit"],
      inputSchema: correlateIpInputSchema,
      handler: async (input) => {
        const result = await services.correlation.correlateIpActivity(input);
        return {
          data: result.result,
          meta: {
            partialFailures: result.partialFailures,
          },
        };
      },
    }),
    defineTool({
      name: "correlate_alert_context",
      description: "Find related events around one alert.",
      inputKeys: ["alertId", "windowMinutes", "limit"],
      inputSchema: correlateAlertInputSchema,
      handler: async (input) => {
        const result = await services.correlation.correlateAlertContext(input);
        return {
          data: result.result,
          meta: {
            partialFailures: result.partialFailures,
          },
        };
      },
    }),
    defineTool({
      name: "summarize_incident",
      description: "Return structured incident summary from alerts and correlated evidence.",
      inputKeys: ["alertIds", "entityIp", "timeRange", "limit"],
      inputSchema: summarizeIncidentInputSchema,
      handler: async (input) => {
        const result = await services.correlation.summarizeIncident(input);
        return {
          data: result.summary,
          meta: {
            partialFailures: result.partialFailures,
          },
        };
      },
    }),
    defineTool({
      name: "reason_about_incident",
      description: "Use optional LLM reasoning over a structured incident summary. Falls back safely when no LLM is configured.",
      inputKeys: ["alertIds", "entityIp", "timeRange", "limit", "question"],
      inputSchema: reasonIncidentInputSchema,
      handler: async (input) => {
        const incident = await services.correlation.summarizeIncident(input);
        const reasoning = await services.reasoning.reasonAboutIncident({
          incident: incident.summary,
          question: input.question,
        });
        return {
          data: {
            incident: incident.summary,
            reasoning,
          },
          meta: {
            partialFailures: incident.partialFailures,
          },
        };
      },
    }),
    defineTool({
      name: "enrich_indicator",
      description: "Normalize and enrich IP, domain, hash, URL, or user indicators.",
      inputKeys: ["type", "value"],
      inputSchema: enrichIndicatorInputSchema,
      handler: async (input) => ({ data: services.enrichment.enrichIndicator(input) }),
    }),
  ];
}
