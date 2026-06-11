import { describe, expect, it } from "vitest";
import { SocAgent } from "../src/agent/workflows.js";
import type { ToolCaller } from "../src/application/ports.js";
import { successEnvelope } from "../src/domain/response.js";
import type { ResponseEnvelope } from "../src/domain/models.js";

describe("SOC agent workflows", () => {
  it("refuses destructive actions", () => {
    const agent = new SocAgent(new EmptyToolCaller());
    const answer = agent.refuseDestructiveRequest("block 203.0.113.10");
    expect(answer.mode).toBe("refusal");
    expect(answer.limitations[0]).toContain("read-only");
  });

  it("triages high severity alerts from tool evidence", async () => {
    const agent = new SocAgent(
      new StaticToolCaller({
        wazuh_get_high_severity_alerts: successEnvelope([
          {
            id: "alert-1",
            timestamp: "2026-06-11T08:00:00.000Z",
            severity: "high",
            severityScore: 12,
            source: "wazuh",
            agent: { id: "001", name: "endpoint-1" },
            rule: { id: "5715", description: "Multiple authentication failures" },
            normalizedFields: {},
          },
        ]),
      }),
    );

    const answer = await agent.triageHighSeverity();
    expect(answer.mode).toBe("triage");
    expect(answer.evidence[0]).toContain("alert-1");
  });
});

class EmptyToolCaller implements ToolCaller {
  public async callTool<TData>(): Promise<ResponseEnvelope<TData>> {
    throw new Error("not used");
  }
}

class StaticToolCaller implements ToolCaller {
  public constructor(private readonly responses: Record<string, ResponseEnvelope<unknown>>) {}

  public async callTool<TData>(name: string): Promise<ResponseEnvelope<TData>> {
    return this.responses[name] as ResponseEnvelope<TData>;
  }
}
