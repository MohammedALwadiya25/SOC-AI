import { describe, expect, it } from "vitest";
import { normalizeAlert } from "../src/application/normalizers.js";
import { sampleAlertSource } from "./helpers.js";

describe("normalizers", () => {
  it("normalizes Wazuh alerts and omits raw log content", () => {
    const alert = normalizeAlert("alert-1", sampleAlertSource);
    expect(alert.id).toBe("alert-1");
    expect(alert.severity).toBe("high");
    expect(alert.network?.sourceIp).toBe("203.0.113.10");
    expect(alert.rule?.mitre?.[0]?.id).toBe("T1110");
    expect(JSON.stringify(alert)).not.toContain("raw log should not be returned");
  });
});
