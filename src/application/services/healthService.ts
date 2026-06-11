import type { WazuhApiClient, WazuhIndexerClient } from "../ports.js";
import type { HealthStatus } from "../../domain/models.js";

export class HealthService {
  public constructor(
    private readonly api: WazuhApiClient,
    private readonly indexer: WazuhIndexerClient,
  ) {}

  public async check(): Promise<HealthStatus> {
    const [apiOk, indexerOk] = await Promise.all([this.api.health(), this.indexer.health()]);
    const ok = apiOk && indexerOk;
    const degraded = apiOk || indexerOk;
    return {
      service: "unified-soc-mcp",
      ok,
      status: ok ? "healthy" : degraded ? "degraded" : "unhealthy",
      dependencies: [
        {
          name: "wazuh_api",
          ok: apiOk,
          status: apiOk ? "healthy" : "unavailable",
          errorCode: apiOk ? undefined : "UPSTREAM_UNAVAILABLE",
        },
        {
          name: "wazuh_indexer",
          ok: indexerOk,
          status: indexerOk ? "healthy" : "unavailable",
          errorCode: indexerOk ? undefined : "UPSTREAM_UNAVAILABLE",
        },
      ],
    };
  }
}
