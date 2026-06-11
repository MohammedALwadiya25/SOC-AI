#!/usr/bin/env node
import { createContainer } from "./infrastructure/container.js";
import { loadConfig } from "./infrastructure/config.js";
import { createLogger } from "./infrastructure/logger.js";
import { toSafeError } from "./domain/errors.js";
import { startStdioServer } from "./mcp/server.js";

async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger(config.logLevel);
  const container = createContainer(config, logger);
  await startStdioServer(container);
}

main().catch((error: unknown) => {
  const safeError = toSafeError(error);
  const logger = createLogger(process.env.LOG_LEVEL ?? "error");
  logger.error(
    {
      success: false,
      errorCode: safeError.code,
    },
    safeError.message,
  );
  process.exitCode = 1;
});
