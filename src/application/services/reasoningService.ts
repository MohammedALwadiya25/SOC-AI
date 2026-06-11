import * as z from "zod/v4";
import type { LlmClient } from "../ports.js";
import { toSafeError } from "../../domain/errors.js";
import type { IncidentSummary, ReasoningResult } from "../../domain/models.js";

const llmReasoningSchema = z
  .object({
    summary: z.string().min(1).max(2000),
    analysis: z.array(z.string().min(1).max(1000)).min(1).max(10),
    recommendations: z.array(z.string().min(1).max(1000)).max(10),
    evidenceUsed: z.array(z.string().min(1).max(500)).max(20),
    confidence: z.enum(["low", "medium", "high"]),
    limitations: z.array(z.string().min(1).max(1000)).max(10),
  })
  .strict();

export class ReasoningService {
  public constructor(private readonly llmClient: LlmClient | null) {}

  public async reasonAboutIncident(input: {
    incident: IncidentSummary;
    question?: string;
  }): Promise<ReasoningResult> {
    const safeIncident = compactIncident(input.incident);

    if (!this.llmClient) {
      return fallbackReasoning(safeIncident, ["LLM is not configured. Deterministic reasoning was used."]);
    }

    try {
      const response = await this.llmClient.completeJson({
        temperature: 0.1,
        maxTokens: 1200,
        messages: [
          {
            role: "system",
            content: [
              "You are a careful SOC analyst.",
              "Use only the JSON evidence provided by the user.",
              "Do not invent alerts, IPs, hostnames, users, hashes, domains, timestamps, containment, or remediation.",
              "Distinguish evidence from inference.",
              "Do not recommend destructive action unless the evidence strongly supports it, and still require human approval.",
              "Return JSON only with keys: summary, analysis, recommendations, evidenceUsed, confidence, limitations.",
            ].join(" "),
          },
          {
            role: "user",
            content: JSON.stringify({
              question: input.question ?? "Explain this incident for a SOC analyst.",
              incident: safeIncident,
            }),
          },
        ],
      });

      const parsed = llmReasoningSchema.parse(response.json);
      return {
        provider: response.provider,
        model: response.model,
        summary: parsed.summary,
        analysis: parsed.analysis,
        recommendations: parsed.recommendations,
        evidenceUsed: parsed.evidenceUsed,
        confidence: parsed.confidence,
        limitations: parsed.limitations,
      };
    } catch (error) {
      const safeError = toSafeError(error);
      return fallbackReasoning(safeIncident, [
        `LLM reasoning failed safely: ${safeError.code}. Deterministic reasoning was used.`,
      ]);
    }
  }
}

function compactIncident(incident: IncidentSummary): IncidentSummary {
  return {
    ...incident,
    timeline: incident.timeline.slice(0, 30),
    evidence: incident.evidence.slice(0, 30),
    mitre: incident.mitre.slice(0, 10),
    recommendedNextSteps: incident.recommendedNextSteps.slice(0, 10),
    limitations: incident.limitations.slice(0, 10),
  };
}

function fallbackReasoning(incident: IncidentSummary, limitations: string[]): ReasoningResult {
  const evidenceUsed = incident.evidence.slice(0, 10).map((entry) => `${entry.source}:${entry.id}`);
  return {
    provider: "fallback",
    summary: `${incident.title}. Severity is ${incident.severity}. Status is ${incident.status}.`,
    analysis: [
      incident.timeline.length > 0
        ? `The incident contains ${incident.timeline.length} timeline event(s).`
        : "No timeline evidence is available.",
      incident.affectedAssets.length > 0
        ? `Affected assets: ${incident.affectedAssets.join(", ")}.`
        : "No affected assets were identified from the available evidence.",
      incident.mitre.length > 0
        ? `MITRE mappings are present with ${incident.mitre.length} mapping result(s).`
        : "No MITRE mapping evidence is available.",
    ],
    recommendations: incident.recommendedNextSteps,
    evidenceUsed,
    confidence: incident.confidence,
    limitations: [...limitations, ...incident.limitations],
  };
}
