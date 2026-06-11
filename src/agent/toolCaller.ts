import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { ToolCaller } from "../application/ports.js";
import type { Logger } from "../application/ports.js";
import { buildToolDefinitions, executeTool } from "../mcp/toolRegistry.js";
import type { AppServices } from "../infrastructure/container.js";
import type { ResponseEnvelope } from "../domain/models.js";
import { errorEnvelope } from "../domain/response.js";

export class InProcessToolCaller implements ToolCaller {
  private readonly definitions: Map<string, ReturnType<typeof buildToolDefinitions>[number]>;

  public constructor(
    private readonly services: AppServices,
    private readonly logger: Logger,
  ) {
    this.definitions = new Map(buildToolDefinitions(this.services).map((definition) => [definition.name, definition]));
  }

  public async callTool<TData>(name: string, args: Record<string, unknown>): Promise<ResponseEnvelope<TData>> {
    const definition = this.definitions.get(name);
    if (!definition) {
      return errorEnvelope({
        code: "NOT_FOUND",
        message: `Tool ${name} was not found.`,
      });
    }
    return (await executeTool(definition, args, this.logger)) as ResponseEnvelope<TData>;
  }
}

export class McpStdioToolCaller implements ToolCaller {
  private readonly client = new Client({
    name: "unified-soc-agent",
    version: "1.0.0",
  });

  private transport?: StdioClientTransport;

  public async connect(server: { command: string; args: string[]; cwd?: string; env?: Record<string, string> }): Promise<void> {
    this.transport = new StdioClientTransport({
      command: server.command,
      args: server.args,
      cwd: server.cwd,
      env: server.env,
      stderr: "inherit",
    });
    await this.client.connect(this.transport);
  }

  public async close(): Promise<void> {
    await this.client.close();
  }

  public async callTool<TData>(name: string, args: Record<string, unknown>): Promise<ResponseEnvelope<TData>> {
    const result = (await this.client.callTool({
      name,
      arguments: args,
    })) as CallToolResult;

    return parseToolEnvelope<TData>(result);
  }
}

function parseToolEnvelope<TData>(result: CallToolResult): ResponseEnvelope<TData> {
  if (isEnvelope<TData>(result.structuredContent)) {
    return result.structuredContent;
  }

  const textContent = result.content.find((entry) => entry.type === "text");
  if (textContent?.type === "text") {
    try {
      const parsed = JSON.parse(textContent.text) as unknown;
      if (isEnvelope<TData>(parsed)) {
        return parsed;
      }
    } catch {
      return errorEnvelope({
        code: "UPSTREAM_BAD_RESPONSE",
        message: "Tool returned non-JSON content.",
      });
    }
  }

  return errorEnvelope({
    code: "UPSTREAM_BAD_RESPONSE",
    message: "Tool response did not contain the unified envelope.",
  });
}

function isEnvelope<TData>(value: unknown): value is ResponseEnvelope<TData> {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as { success?: unknown; meta?: unknown };
  return typeof candidate.success === "boolean" && typeof candidate.meta === "object" && candidate.meta !== null;
}
