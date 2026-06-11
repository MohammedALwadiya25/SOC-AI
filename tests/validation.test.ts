import { describe, expect, it } from "vitest";
import {
  correlateIpInputSchema,
  enrichIndicatorInputSchema,
  mitreTechniqueInputSchema,
  timeRangeSchema,
} from "../src/mcp/schemas.js";

describe("input validation", () => {
  it("rejects malformed IP addresses", () => {
    expect(() => correlateIpInputSchema.parse({ ip: "999.1.1.1" })).toThrow();
  });

  it("rejects unsupported indicator value for declared type", () => {
    expect(() => enrichIndicatorInputSchema.parse({ type: "domain", value: "not a domain" })).toThrow();
  });

  it("rejects invalid MITRE technique identifiers", () => {
    expect(() => mitreTechniqueInputSchema.parse({ techniqueId: "TA0001" })).toThrow();
  });

  it("rejects reversed time ranges", () => {
    expect(() =>
      timeRangeSchema.parse({
        start: "2026-06-11T10:00:00.000Z",
        end: "2026-06-11T09:00:00.000Z",
      }),
    ).toThrow();
  });
});
