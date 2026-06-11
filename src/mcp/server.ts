import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { AppContainer } from "../infrastructure/container.js";
import { registerSocTools } from "./toolRegistry.js";

export function createMcpServer(container: AppContainer): McpServer {
  const server = new McpServer({
    name: container.config.mcpServerName,
    version: container.config.mcpServerVersion,
  });
  registerSocTools(server, container.services, container.logger);
  return server;
}

export async function startStdioServer(container: AppContainer): Promise<void> {
  const server = createMcpServer(container);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  container.logger.info(
    {
      service: container.config.mcpServerName,
      version: container.config.mcpServerVersion,
      transport: "stdio",
      success: true,
    },
    "MCP server started",
  );
}
