import type { Logger, WazuhIndexerClient, IndexerSearchRequest, IndexerSearchResponse, WazuhApiClient } from "../src/application/ports.js";
import type { AppConfig } from "../src/infrastructure/config.js";
import type { WazuhAgent } from "../src/domain/models.js";

export const testLogger: Logger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

export const testConfig: AppConfig = {
  nodeEnv: "test",
  logLevel: "silent",
  mcpServerName: "test-server",
  mcpServerVersion: "1.0.0",
  wazuhApiUrl: undefined,
  wazuhApiUsername: undefined,
  wazuhApiPassword: undefined,
  wazuhIndexerUrl: undefined,
  wazuhIndexerUsername: undefined,
  wazuhIndexerPassword: undefined,
  alertIndex: "wazuh-alerts-*",
  zeekIndex: "wazuh-alerts-*",
  suricataIndex: "wazuh-alerts-*",
  tlsRejectUnauthorized: true,
  httpTimeoutMs: 1000,
  httpRetryAttempts: 0,
  httpRetryBaseDelayMs: 1,
  defaultLimit: 50,
  maxLimit: 500,
  defaultTimeRangeHours: 24,
  llmProvider: "disabled",
  llmBaseUrl: "https://api.openai.com",
  llmApiKey: undefined,
  llmModel: undefined,
  llmTimeoutMs: 1000,
};

export class FakeIndexerClient implements WazuhIndexerClient {
  public requests: IndexerSearchRequest[] = [];

  public constructor(private readonly responder: (request: IndexerSearchRequest) => Promise<IndexerSearchResponse> | IndexerSearchResponse) {}

  public async health(): Promise<boolean> {
    return true;
  }

  public async search(request: IndexerSearchRequest): Promise<IndexerSearchResponse> {
    this.requests.push(request);
    return this.responder(request);
  }
}

export class FakeWazuhApiClient implements WazuhApiClient {
  public async health(): Promise<boolean> {
    return true;
  }

  public async listAgents(): Promise<WazuhAgent[]> {
    return [
      {
        id: "001",
        name: "endpoint-1",
        status: "active",
        ip: "10.0.0.5",
      },
    ];
  }

  public async getAgent(agentId: string): Promise<WazuhAgent | null> {
    return {
      id: agentId,
      name: "endpoint-1",
      status: "active",
      ip: "10.0.0.5",
    };
  }
}

export const sampleAlertSource = {
  "@timestamp": "2026-06-11T08:00:00.000Z",
  agent: {
    id: "001",
    name: "endpoint-1",
    ip: "10.0.0.5",
  },
  rule: {
    id: "5715",
    level: 12,
    description: "Multiple authentication failures",
    groups: ["authentication_failed", "pci_dss_10.2.4"],
    mitre: {
      id: ["T1110"],
      tactic: ["Credential Access"],
      technique: ["Brute Force"],
    },
  },
  data: {
    srcip: "203.0.113.10",
    dstip: "10.0.0.5",
    srcport: "4444",
    dstport: "22",
    protocol: "tcp",
  },
  full_log: "raw log should not be returned",
};
