import { describe, expect, it } from "vitest";
import { AppError, ERROR_CODES } from "../src/domain/errors.js";
import { AlertService } from "../src/application/services/alertService.js";
import { CorrelationService } from "../src/application/services/correlationService.js";
import { MitreService } from "../src/application/services/mitreService.js";
import { SuricataService } from "../src/application/services/suricataService.js";
import { ZeekService } from "../src/application/services/zeekService.js";
import { FakeIndexerClient, sampleAlertSource, testConfig } from "./helpers.js";

describe("correlation", () => {
  it("returns partial failures when one evidence source fails", async () => {
    const indexer = new FakeIndexerClient((request) => {
      const body = JSON.stringify(request.body);
      if (body.includes("zeek")) {
        throw new AppError(ERROR_CODES.UPSTREAM_UNAVAILABLE, "Zeek indexed data unavailable.");
      }
      return {
        total: 1,
        hits: [{ id: "alert-1", source: sampleAlertSource }],
      };
    });
    const context = { config: testConfig };
    const alerts = new AlertService(indexer, context);
    const zeek = new ZeekService(indexer, context);
    const suricata = new SuricataService(indexer, context);
    const mitre = new MitreService(alerts);
    const correlation = new CorrelationService(alerts, zeek, suricata, mitre, context);

    const result = await correlation.correlateIpActivity({ ip: "203.0.113.10" });
    expect(result.result.timeline.length).toBeGreaterThan(0);
    expect(result.partialFailures).toEqual([
      {
        source: "zeek",
        code: ERROR_CODES.UPSTREAM_UNAVAILABLE,
        message: "Zeek indexed data unavailable.",
      },
    ]);
  });
});
