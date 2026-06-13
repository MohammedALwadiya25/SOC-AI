import "dotenv/config";
import * as z from "zod/v4";
import { AppError, ERROR_CODES } from "../domain/errors.js";

const boolSchema = z
  .string()
  .optional()
  .transform((value) => {
    if (value === undefined || value.trim() === "") {
      return undefined;
    }
    return value.toLowerCase() === "true";
  });

const intSchema = (defaultValue: number, min: number, max: number) =>
  z
    .string()
    .optional()
    .transform((value) => (value === undefined || value.trim() === "" ? defaultValue : Number(value)))
    .refine((value) => Number.isInteger(value) && value >= min && value <= max);

const urlFromEnvSchema = z
  .string()
  .url()
  .refine((value) => value.startsWith("https://"), "URL must use HTTPS.");

const llmUrlFromEnvSchema = z
  .string()
  .url()
  .refine(
    (value) => value.startsWith("https://") || /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/.test(value),
    "LLM base URL must use HTTPS unless it points to localhost.",
  );

const configSchema = z.object({
  nodeEnv: z.enum(["development", "test", "production"]).default("development"),
  logLevel: z.string().default("info"),
  mcpServerName: z.string().min(1).default("unified-soc-mcp"),
  mcpServerVersion: z.string().min(1).default("1.0.0"),
  wazuhApiUrl: urlFromEnvSchema.optional(),
  wazuhApiUsername: z.string().optional(),
  wazuhApiPassword: z.string().optional(),
  wazuhIndexerUrl: urlFromEnvSchema.optional(),
  wazuhIndexerUsername: z.string().optional(),
  wazuhIndexerPassword: z.string().optional(),
  alertIndex: z.string().min(1).default("wazuh-alerts-*"),
  zeekIndex: z.string().min(1).default("wazuh-archives-4.x-*"),
  suricataIndex: z.string().min(1).default("wazuh-alerts-*"),
  tlsRejectUnauthorized: boolSchema.default(true),
  httpTimeoutMs: intSchema(10_000, 500, 120_000),
  httpRetryAttempts: intSchema(2, 0, 5),
  httpRetryBaseDelayMs: intSchema(250, 50, 5_000),
  defaultLimit: intSchema(50, 1, 500),
  maxLimit: intSchema(500, 1, 500),
  defaultTimeRangeHours: intSchema(24, 1, 24 * 31),
  llmProvider: z.enum(["disabled", "openai-compatible"]).default("disabled"),
  llmBaseUrl: llmUrlFromEnvSchema.default("https://api.openai.com"),
  llmApiKey: z.string().optional(),
  llmModel: z.string().min(1).optional(),
  llmTimeoutMs: intSchema(20_000, 500, 120_000),
});

export type AppConfig = z.infer<typeof configSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const parsed = configSchema.safeParse({
    nodeEnv: env.NODE_ENV,
    logLevel: env.LOG_LEVEL,
    mcpServerName: env.MCP_SERVER_NAME,
    mcpServerVersion: env.MCP_SERVER_VERSION,
    wazuhApiUrl: env.WAZUH_API_URL,
    wazuhApiUsername: env.WAZUH_API_USERNAME,
    wazuhApiPassword: env.WAZUH_API_PASSWORD,
    wazuhIndexerUrl: env.WAZUH_INDEXER_URL,
    wazuhIndexerUsername: env.WAZUH_INDEXER_USERNAME,
    wazuhIndexerPassword: env.WAZUH_INDEXER_PASSWORD,
    alertIndex: env.WAZUH_INDEXER_ALERT_INDEX,
    zeekIndex: env.WAZUH_INDEXER_ZEEK_INDEX,
    suricataIndex: env.WAZUH_INDEXER_SURICATA_INDEX,
    tlsRejectUnauthorized: env.TLS_REJECT_UNAUTHORIZED,
    httpTimeoutMs: env.HTTP_TIMEOUT_MS,
    httpRetryAttempts: env.HTTP_RETRY_ATTEMPTS,
    httpRetryBaseDelayMs: env.HTTP_RETRY_BASE_DELAY_MS,
    defaultLimit: env.DEFAULT_LIMIT,
    maxLimit: env.MAX_LIMIT,
    defaultTimeRangeHours: env.DEFAULT_TIME_RANGE_HOURS,
    llmProvider: env.LLM_PROVIDER,
    llmBaseUrl: env.LLM_BASE_URL,
    llmApiKey: env.LLM_API_KEY,
    llmModel: env.LLM_MODEL,
    llmTimeoutMs: env.LLM_TIMEOUT_MS,
  });

  if (!parsed.success) {
    throw new AppError(ERROR_CODES.CONFIGURATION, "Invalid application configuration.", {
      issues: parsed.error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  if (parsed.data.defaultLimit > parsed.data.maxLimit) {
    throw new AppError(ERROR_CODES.CONFIGURATION, "DEFAULT_LIMIT must not exceed MAX_LIMIT.");
  }

  return parsed.data;
}
