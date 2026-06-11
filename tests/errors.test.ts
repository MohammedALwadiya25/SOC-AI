import { describe, expect, it } from "vitest";
import { AppError, ERROR_CODES, redactSecrets, toSafeError } from "../src/domain/errors.js";

describe("safe errors and redaction", () => {
  it("redacts secret-like fields recursively", () => {
    expect(
      redactSecrets({
        username: "soc",
        password: "secret",
        nested: {
          authorization: "Bearer abc.def",
        },
      }),
    ).toEqual({
      username: "soc",
      password: "[REDACTED]",
      nested: {
        authorization: "[REDACTED]",
      },
    });
  });

  it("does not expose unknown exception messages", () => {
    const safe = toSafeError(new Error("C:\\Users\\secret\\stack.txt token=abc"));
    expect(safe.code).toBe(ERROR_CODES.INTERNAL);
    expect(safe.message).not.toContain("secret");
  });

  it("returns app errors with sanitized details", () => {
    const safe = toSafeError(new AppError(ERROR_CODES.UPSTREAM_AUTH, "Authentication failed.", { token: "abc" }));
    expect(safe).toEqual({
      code: ERROR_CODES.UPSTREAM_AUTH,
      message: "Authentication failed.",
      details: {
        token: "[REDACTED]",
      },
    });
  });
});
