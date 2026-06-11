import { describe, expect, it } from "vitest";
import type { LlmClient, LlmJsonRequest, LlmJsonResponse } from "../src/application/ports.js";
import { ReasoningService } from "../src/application/services/reasoningService.js";
import type { IncidentSummary } from "../src/domain/models.js";

describe("ReasoningService", () => {
  it("returns safe fallback reasoning when no LLM is configured", async () => {
    const service = new ReasoningService(null);
    const result = await service.reasonAboutIncident({ incident: sampleIncident });

    expect(result.provider).toBe("fallback");
    expect(result.limitations[0]).toContain("LLM is not configured");
    expect(result.summary).toContain("Test incident");
  });

  it("uses LLM JSON when configured", async () => {
    const service = new ReasoningService(new FakeLlmClient());
    const result = await service.reasonAboutIncident({
      incident: sampleIncident,
      question: "Explain this simply.",
    });

    expect(result.provider).toBe("openai-compatible");
    expect(result.model).toBe("test-model");
    expect(result.summary).toBe("LLM summary from evidence.");
  });

  it("falls back safely when LLM output is invalid", async () => {
    const service = new ReasoningService(new InvalidLlmClient());
    const result = await service.reasonAboutIncident({ incident: sampleIncident });

    expect(result.provider).toBe("fallback");
    expect(result.limitations[0]).toContain("LLM reasoning failed safely");
  });
});

const sampleIncident: IncidentSummary = {
  title: "Test incident",
  severity: "high",
  status: "triaged",
  affectedAssets: ["endpoint-1"],
  timeline: [
    {
      timestamp: "2026-06-11T08:00:00.000Z",
      source: "wazuh",
      title: "Multiple authentication failures",
      severity: "high",
      evidenceId: "alert-1",
      details: {
        ruleId: "5715",
      },
    },
  ],
  evidence: [
    {
      source: "wazuh",
      id: "alert-1",
      summary: "Multiple authentication failures",
    },
  ],
  mitre: [],
  confidence: "medium",
  recommendedNextSteps: ["Validate whether the authentication failures are expected."],
  limitations: [],
};

class FakeLlmClient implements LlmClient {
  public async completeJson(_request: LlmJsonRequest): Promise<LlmJsonResponse> {
    return {
      provider: "openai-compatible",
      model: "test-model",
      json: {
        summary: "LLM summary from evidence.",
        analysis: ["The evidence shows repeated authentication failures."],
        recommendations: ["Review source IP and affected account."],
        evidenceUsed: ["wazuh:alert-1"],
        confidence: "medium",
        limitations: ["No host containment evidence was provided."],
      },
    };
  }
}

class InvalidLlmClient implements LlmClient {
  public async completeJson(_request: LlmJsonRequest): Promise<LlmJsonResponse> {
    return {
      provider: "openai-compatible",
      model: "bad-model",
      json: {
        nope: true,
      },
    };
  }
}
