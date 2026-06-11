import { describe, expect, it } from "vitest";
import { AlertService } from "../src/application/services/alertService.js";
import { WazuhAgentService } from "../src/application/services/agentService.js";
import { CorrelationService } from "../src/application/services/correlationService.js";
import { EnrichmentService } from "../src/application/services/enrichmentService.js";
import { HealthService } from "../src/application/services/healthService.js";
import { MitreService } from "../src/application/services/mitreService.js";
import { ReasoningService } from "../src/application/services/reasoningService.js";
import { SuricataService } from "../src/application/services/suricataService.js";
import { ZeekService } from "../src/application/services/zeekService.js";
import { buildToolDefinitions, executeTool } from "../src/mcp/toolRegistry.js";
import { FakeIndexerClient, FakeWazuhApiClient, sampleAlertSource, testConfig, testLogger } from "./helpers.js";

describe("tool execution", () => {
  it("returns the unified envelope for successful tools", async () => {
    const indexer = new FakeIndexerClient(() => ({
      total: 1,
      hits: [{ id: "alert-1", source: sampleAlertSource }],
    }));
    const services = buildServices(indexer);
    const tool = buildToolDefinitions(services).find((definition) => definition.name === "wazuh_get_high_severity_alerts");
    expect(tool).toBeDefined();

    const envelope = await executeTool(tool!, { limit: 1 }, testLogger);
    expect(envelope.success).toBe(true);
    expect(envelope.meta.tool).toBe("wazuh_get_high_severity_alerts");
    expect(envelope.meta.pagination?.returned).toBe(1);
  });

  it("returns a validation envelope without throwing", async () => {
    const services = buildServices(
      new FakeIndexerClient(() => ({
        total: 0,
        hits: [],
      })),
    );
    const tool = buildToolDefinitions(services).find((definition) => definition.name === "correlate_ip_activity");
    expect(tool).toBeDefined();

    const envelope = await executeTool(tool!, { ip: "bad-ip" }, testLogger);
    expect(envelope.success).toBe(false);
    expect(envelope.error?.code).toBe("VALIDATION_ERROR");
  });
});

function buildServices(indexer: FakeIndexerClient) {
  const context = { config: testConfig };
  const api = new FakeWazuhApiClient();
  const alerts = new AlertService(indexer, context);
  const agents = new WazuhAgentService(api, context);
  const zeek = new ZeekService(indexer, context);
  const suricata = new SuricataService(indexer, context);
  const mitre = new MitreService(alerts);
  const correlation = new CorrelationService(alerts, zeek, suricata, mitre, context);
  return {
    alerts,
    agents,
    zeek,
    suricata,
    mitre,
    correlation,
    enrichment: new EnrichmentService(),
    health: new HealthService(api, indexer),
    reasoning: new ReasoningService(null),
  };
}
