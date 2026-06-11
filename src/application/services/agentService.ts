import type { WazuhApiClient } from "../ports.js";
import type { WazuhAgent } from "../../domain/models.js";
import { AppError, ERROR_CODES } from "../../domain/errors.js";
import { effectiveLimit, type ServiceContext } from "./context.js";

export class WazuhAgentService {
  public constructor(
    private readonly api: WazuhApiClient,
    private readonly context: ServiceContext,
  ) {}

  public async listAgents(input: { status?: string; osPlatform?: string; limit?: number }): Promise<WazuhAgent[]> {
    return this.api.listAgents({
      status: input.status,
      osPlatform: input.osPlatform,
      limit: effectiveLimit(input.limit, this.context),
    });
  }

  public async getAgentStatus(agentId: string): Promise<WazuhAgent> {
    const agent = await this.api.getAgent(agentId);
    if (!agent) {
      throw new AppError(ERROR_CODES.NOT_FOUND, "Agent was not found.", { agentId });
    }
    return agent;
  }

  public async getAgentSummary(agentId: string): Promise<WazuhAgent> {
    return this.getAgentStatus(agentId);
  }
}
