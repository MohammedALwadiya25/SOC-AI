import type { Logger } from "../application/ports.js";
import { AlertService } from "../application/services/alertService.js";
import { WazuhAgentService } from "../application/services/agentService.js";
import { CorrelationService } from "../application/services/correlationService.js";
import { EnrichmentService } from "../application/services/enrichmentService.js";
import { HealthService } from "../application/services/healthService.js";
import { MitreService } from "../application/services/mitreService.js";
import { ReasoningService } from "../application/services/reasoningService.js";
import { SuricataService } from "../application/services/suricataService.js";
import { ZeekService } from "../application/services/zeekService.js";
import type { AppConfig } from "./config.js";
import { HttpJsonClient } from "./httpClient.js";
import { OpenAiCompatibleLlmClient } from "./llmClient.js";
import { UnavailableIndexerClient, UnavailableWazuhApiClient } from "./unavailableClients.js";
import { WazuhApiHttpClient } from "./wazuhApiClient.js";
import { WazuhIndexerHttpClient } from "./wazuhIndexerClient.js";

export interface AppServices {
  alerts: AlertService;
  agents: WazuhAgentService;
  zeek: ZeekService;
  suricata: SuricataService;
  mitre: MitreService;
  correlation: CorrelationService;
  enrichment: EnrichmentService;
  health: HealthService;
  reasoning: ReasoningService;
}

export interface AppContainer {
  config: AppConfig;
  logger: Logger;
  services: AppServices;
}

export function createContainer(config: AppConfig, logger: Logger): AppContainer {
  const context = { config };
  const indexer =
    config.wazuhIndexerUrl && config.wazuhIndexerUsername && config.wazuhIndexerPassword
      ? new WazuhIndexerHttpClient(
          new HttpJsonClient({
            baseUrl: config.wazuhIndexerUrl,
            timeoutMs: config.httpTimeoutMs,
            retryAttempts: config.httpRetryAttempts,
            retryBaseDelayMs: config.httpRetryBaseDelayMs,
            tlsRejectUnauthorized: config.tlsRejectUnauthorized,
          }),
          {
            username: config.wazuhIndexerUsername,
            password: config.wazuhIndexerPassword,
          },
        )
      : new UnavailableIndexerClient();

  const api =
    config.wazuhApiUrl && config.wazuhApiUsername && config.wazuhApiPassword
      ? new WazuhApiHttpClient(
          new HttpJsonClient({
            baseUrl: config.wazuhApiUrl,
            timeoutMs: config.httpTimeoutMs,
            retryAttempts: config.httpRetryAttempts,
            retryBaseDelayMs: config.httpRetryBaseDelayMs,
            tlsRejectUnauthorized: config.tlsRejectUnauthorized,
          }),
          {
            username: config.wazuhApiUsername,
            password: config.wazuhApiPassword,
          },
        )
      : new UnavailableWazuhApiClient();

  const alerts = new AlertService(indexer, context);
  const agents = new WazuhAgentService(api, context);
  const zeek = new ZeekService(indexer, context);
  const suricata = new SuricataService(indexer, context);
  const mitre = new MitreService(alerts);
  const correlation = new CorrelationService(alerts, zeek, suricata, mitre, context);
  const enrichment = new EnrichmentService();
  const health = new HealthService(api, indexer);
  const llmClient =
    config.llmProvider === "openai-compatible" && config.llmApiKey && config.llmModel
      ? new OpenAiCompatibleLlmClient(
          new HttpJsonClient({
            baseUrl: config.llmBaseUrl,
            timeoutMs: config.llmTimeoutMs,
            retryAttempts: config.httpRetryAttempts,
            retryBaseDelayMs: config.httpRetryBaseDelayMs,
            tlsRejectUnauthorized: config.tlsRejectUnauthorized,
          }),
          config.llmApiKey,
          config.llmModel,
        )
      : null;
  const reasoning = new ReasoningService(llmClient);

  return {
    config,
    logger,
    services: {
      alerts,
      agents,
      zeek,
      suricata,
      mitre,
      correlation,
      enrichment,
      health,
      reasoning,
    },
  };
}
