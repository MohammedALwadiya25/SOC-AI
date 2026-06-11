import pino from "pino";
import type { Logger } from "../application/ports.js";
import { redactSecrets } from "../domain/errors.js";

export function createLogger(level: string): Logger {
  const logger = pino(
    {
      level,
      redact: {
        paths: [
          "password",
          "*.password",
          "token",
          "*.token",
          "authorization",
          "*.authorization",
          "apiKey",
          "*.apiKey",
          "connectionString",
          "*.connectionString",
        ],
        censor: "[REDACTED]",
      },
    },
    process.stderr,
  );

  return {
    info: (event, message) => logger.info(redactSecrets(event), message),
    warn: (event, message) => logger.warn(redactSecrets(event), message),
    error: (event, message) => logger.error(redactSecrets(event), message),
  };
}
