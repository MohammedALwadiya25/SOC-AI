import type { IndicatorContext, IndicatorType } from "../../domain/models.js";
import { isPrivateIp, normalizeIndicator } from "../../utils/indicator.js";

export class EnrichmentService {
  public enrichIndicator(input: { type: IndicatorType; value: string }): IndicatorContext {
    const normalizedValue = normalizeIndicator(input.type, input.value);

    if (input.type === "ip") {
      return {
        type: input.type,
        value: input.value,
        normalizedValue,
        classification: isPrivateIp(normalizedValue) ? "private" : "public",
        notes: [
          isPrivateIp(normalizedValue)
            ? "Private or local address. Interpret role using internal network context."
            : "Public address. External reputation is not queried in V1.",
        ],
      };
    }

    if (input.type === "user") {
      return {
        type: input.type,
        value: input.value,
        normalizedValue,
        classification: "user",
        notes: ["User enrichment is limited to normalization in V1."],
      };
    }

    return {
      type: input.type,
      value: input.value,
      normalizedValue,
      classification: "unknown",
      notes: ["External threat intelligence enrichment is not enabled in V1."],
    };
  }
}
