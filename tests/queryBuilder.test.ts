import { describe, expect, it } from "vitest";
import { buildSearchBody } from "../src/application/queryBuilder.js";

describe("query builder", () => {
  it("uses range filter for minimum severity", () => {
    const body = buildSearchBody({
      limit: 10,
      filters: [{ field: "rule.level", value: 10, operator: "range_gte" }],
    });
    expect(JSON.stringify(body)).toContain('"gte":10');
  });

  it("uses multi_match instead of query-string interpolation for keywords", () => {
    const body = buildSearchBody({
      limit: 10,
      keyword: "failed login OR *",
      keywordFields: ["rule.description"],
    });
    expect(JSON.stringify(body)).toContain("multi_match");
    expect(JSON.stringify(body)).not.toContain("query_string");
  });
});
