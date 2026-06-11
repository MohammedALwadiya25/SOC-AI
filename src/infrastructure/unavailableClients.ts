import type { WazuhApiClient, WazuhIndexerClient, IndexerSearchRequest, IndexerSearchResponse } from "../application/ports.js";
import { AppError, ERROR_CODES } from "../domain/errors.js";
import type { WazuhAgent } from "../domain/models.js";

export class UnavailableIndexerClient implements WazuhIndexerClient {
  public async health(): Promise<boolean> {
    return false;
  }

  public async search(_request: IndexerSearchRequest): Promise<IndexerSearchResponse> {
    throw new AppError(ERROR_CODES.CONFIGURATION, "Wazuh Indexer is not configured.");
  }
}

export class UnavailableWazuhApiClient implements WazuhApiClient {
  public async health(): Promise<boolean> {
    return false;
  }

  public async listAgents(_input: { limit: number; status?: string; osPlatform?: string }): Promise<WazuhAgent[]> {
    throw new AppError(ERROR_CODES.CONFIGURATION, "Wazuh API is not configured.");
  }

  public async getAgent(_agentId: string): Promise<WazuhAgent | null> {
    throw new AppError(ERROR_CODES.CONFIGURATION, "Wazuh API is not configured.");
  }
}
