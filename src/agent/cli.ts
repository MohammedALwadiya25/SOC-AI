#!/usr/bin/env node
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { McpStdioToolCaller } from "./toolCaller.js";
import { SocAgent } from "./workflows.js";

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  const caller = new McpStdioToolCaller();
  await caller.connect(defaultServer());
  try {
    const agent = new SocAgent(caller);
    const answer = await dispatch(agent, command, args);
    process.stdout.write(`${JSON.stringify(answer, null, 2)}\n`);
  } finally {
    await caller.close();
  }
}

async function dispatch(agent: SocAgent, command: string | undefined, args: string[]) {
  if (!command || command === "health") {
    return agent.health();
  }
  if (command === "triage") {
    return agent.triageHighSeverity();
  }
  if (command === "alert" && args[0]) {
    return agent.investigateAlert(args[0]);
  }
  if (command === "ip" && args[0]) {
    return agent.investigateIp(args[0]);
  }
  if (command === "technique" && args[0]) {
    return agent.explainTechnique(args[0]);
  }
  if (command === "report-ip" && args[0]) {
    return agent.summarizeIncident({ entityIp: args[0] });
  }
  if (command === "block" || command === "restart" || command === "modify" || command === "delete") {
    return agent.refuseDestructiveRequest([command, ...args].join(" "));
  }
  return {
    mode: "clarification" as const,
    title: "Unsupported agent command",
    evidence: [],
    analysis: ["Supported commands: health, triage, alert <id>, ip <ip>, technique <id>, report-ip <ip>."],
    recommendations: ["Provide a supported command and the required identifier."],
    limitations: [],
  };
}

function defaultServer(): { command: string; args: string[]; cwd?: string; env?: Record<string, string> } {
  if (process.env.MCP_SERVER_COMMAND) {
    return {
      command: process.env.MCP_SERVER_COMMAND,
      args: process.env.MCP_SERVER_ARGS ? process.env.MCP_SERVER_ARGS.split(" ").filter(Boolean) : [],
      cwd: process.cwd(),
      env: process.env as Record<string, string>,
    };
  }

  const currentDir = dirname(fileURLToPath(import.meta.url));
  return {
    command: process.execPath,
    args: [resolve(currentDir, "../index.js")],
    cwd: process.cwd(),
    env: process.env as Record<string, string>,
  };
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Agent failed.";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
