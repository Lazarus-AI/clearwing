import readline from "node:readline";
import { randomUUID } from "node:crypto";
import process from "node:process";

import {
  createAssistantMessageEventStream,
  InMemoryCredentialStore,
  Type,
} from "@earendil-works/pi-ai";
import {
  createAgentSession,
  createExtensionRuntime,
  ModelRuntime,
  SessionManager,
  SettingsManager,
} from "@earendil-works/pi-coding-agent";

const PROTOCOL_VERSION = 1;
const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
let protocolSecret = "";

function safeMessage(value) {
  let message = value instanceof Error ? value.message : String(value);
  if (protocolSecret) message = message.split(protocolSecret).join("[REDACTED]");
  return message.slice(0, 2000);
}

function send(message) {
  const encoded = JSON.stringify(message);
  if (Buffer.byteLength(encoded, "utf8") > MAX_MESSAGE_BYTES) {
    throw new Error("CyberPi protocol message exceeds the size limit");
  }
  process.stdout.write(`${encoded}\n`);
}

function fail(message) {
  send({ type: "error", message: safeMessage(message) });
}

function readMessages() {
  const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const iterator = input[Symbol.asyncIterator]();
  return {
    input,
    async next() {
      const item = await iterator.next();
      if (item.done) throw new Error("Clearwing closed the CyberPi protocol");
      if (Buffer.byteLength(item.value, "utf8") > MAX_MESSAGE_BYTES) {
        throw new Error("CyberPi protocol message exceeds the size limit");
      }
      const value = JSON.parse(item.value);
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("CyberPi protocol messages must be JSON objects");
      }
      return value;
    },
  };
}

function resourceLoader(systemPrompt) {
  return {
    getExtensions: () => ({ extensions: [], errors: [], runtime: createExtensionRuntime() }),
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () => systemPrompt,
    getSystemPromptSource: () => undefined,
    getAppendSystemPrompt: () => [],
    getAppendSystemPromptSources: () => [],
    extendResources: () => {},
    reload: async () => {},
  };
}

function customTools(definitions, protocol) {
  return definitions.map((definition) => ({
    name: definition.name,
    label: definition.name,
    description: definition.description,
    parameters: Type.Unsafe(definition.schema),
    executionMode: "sequential",
    async execute(toolCallId, params) {
      send({ type: "tool_call", id: toolCallId, name: definition.name, arguments: params });
      const response = await protocol.next();
      if (response.type !== "tool_result" || response.id !== toolCallId) {
        throw new Error(`Unexpected Clearwing tool response for ${toolCallId}`);
      }
      const text =
        typeof response.result === "string" ? response.result : JSON.stringify(response.result ?? null);
      if (response.ok !== true) throw new Error(text);
      return {
        content: [{ type: "text", text }],
        details: response.result,
      };
    },
  }));
}

function usageAccumulator() {
  const totals = {
    input_tokens: 0,
    output_tokens: 0,
    cached_input_tokens: 0,
    total_tokens: 0,
    cost_usd: 0,
  };
  return {
    totals,
    calls: 0,
    error: undefined,
    add(message) {
      if (message?.role !== "assistant" || !message.usage) return;
      totals.input_tokens +=
        Number(message.usage.input || 0) +
        Number(message.usage.cacheRead || 0) +
        Number(message.usage.cacheWrite || 0);
      totals.output_tokens += Number(message.usage.output || 0);
      totals.cached_input_tokens += Number(message.usage.cacheRead || 0);
      totals.total_tokens += Number(message.usage.totalTokens || 0);
      totals.cost_usd += Number(message.usage.cost?.total || 0);
    },
  };
}

function errorMessage(model, error) {
  return {
    role: "assistant",
    content: [],
    api: model.api,
    provider: model.provider,
    model: model.id,
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason: "error",
    errorMessage: safeMessage(error),
    timestamp: Date.now(),
  };
}

function trajectoryMessage(message) {
  const content = Array.isArray(message.content) ? message.content : [];
  const text = content
    .filter((part) => part?.type === "text")
    .map((part) => String(part.text || ""))
    .join("");
  const reasoning = content
    .filter((part) => part?.type === "thinking")
    .map((part) => String(part.thinking || ""))
    .join("");
  const toolCalls = content
    .filter((part) => part?.type === "toolCall")
    .map((part) => ({
      call_id: String(part.id || ""),
      fn_name: String(part.name || ""),
      fn_arguments: part.arguments || {},
      fn_arguments_json: JSON.stringify(part.arguments || {}),
    }));
  return {
    message: {
      role: "assistant",
      content: text,
      tool_calls: toolCalls,
      tool_response_call_id: null,
    },
    reasoning_content: reasoning,
    usage: {
      input_tokens:
        Number(message.usage?.input || 0) +
        Number(message.usage?.cacheRead || 0) +
        Number(message.usage?.cacheWrite || 0),
      output_tokens: Number(message.usage?.output || 0),
      total_tokens: Number(message.usage?.totalTokens || 0),
    },
    model: String(message.model || ""),
  };
}

function meteredStream(originalStream, protocol, request, meter) {
  return async (model, context, options = {}) => {
    const id = randomUUID();
    const clearwingMaxTokens = Number(request.model.max_output_tokens);
    const requestedMaxTokens = Math.min(
      Number(options.maxTokens || model.maxTokens),
      Number.isInteger(clearwingMaxTokens) && clearwingMaxTokens > 0
        ? clearwingMaxTokens
        : Number.POSITIVE_INFINITY,
    );
    send({
      type: "model_call",
      id,
      input_bytes: Buffer.byteLength(JSON.stringify(context), "utf8"),
      max_tokens: requestedMaxTokens,
    });
    const authorization = await protocol.next();
    if (authorization.type !== "model_authorization" || authorization.id !== id) {
      throw new Error(`Unexpected Clearwing model authorization for ${id}`);
    }
    if (!Number.isInteger(authorization.max_tokens) || authorization.max_tokens < 1) {
      throw new Error(`Invalid Clearwing output limit for ${id}`);
    }
    meter.calls += 1;
    const upstream = await originalStream(model, context, {
      ...options,
      temperature: request.model.temperature,
      samplingParams: { ...options.samplingParams, top_p: request.model.top_p },
      maxTokens: authorization.max_tokens,
    });
    const output = createAssistantMessageEventStream();
    void (async () => {
      let finalized = false;
      for await (const event of upstream) {
        if (event.type === "done" || event.type === "error") {
          finalized = true;
          const message = event.type === "done" ? event.message : event.error;
          meter.add(message);
          send({
            type: "model_result",
            id,
            ok: event.type === "done",
            error:
              event.type === "error"
                ? safeMessage(message.errorMessage || message.stopReason)
                : undefined,
            usage: {
              input_tokens:
                Number(message.usage?.input || 0) +
                Number(message.usage?.cacheRead || 0) +
                Number(message.usage?.cacheWrite || 0),
              output_tokens: Number(message.usage?.output || 0),
              cached_input_tokens: Number(message.usage?.cacheRead || 0),
              total_tokens: Number(message.usage?.totalTokens || 0),
              cost_usd: Number(message.usage?.cost?.total || 0),
            },
          });
          const acknowledgment = await protocol.next();
          if (acknowledgment.type !== "model_result_ack" || acknowledgment.id !== id) {
            throw new Error(`Unexpected Clearwing model-result acknowledgment for ${id}`);
          }
        }
        output.push(event);
      }
      if (!finalized) throw new Error("Pi provider stream ended without a result");
    })().catch((error) => {
      meter.error = error;
      output.push({ type: "error", reason: "error", error: errorMessage(model, error) });
    });
    return output;
  };
}

async function run() {
  const protocol = readMessages();
  let session;
  try {
    const request = await protocol.next();
    if (request.type !== "start" || request.protocol !== PROTOCOL_VERSION) {
      throw new Error("Unsupported CyberPi protocol");
    }
    const apiKey = process.env.CLEARWING_CYBERPI_API_KEY;
    delete process.env.CLEARWING_CYBERPI_API_KEY;
    if (!apiKey) throw new Error("CyberPi API key was not provided");
    protocolSecret = apiKey;

    const credentials = new InMemoryCredentialStore();
    await credentials.modify(request.model.provider, async () => ({ type: "api_key", key: apiKey }));
    const modelRuntime = await ModelRuntime.create({
      credentials,
      modelsPath: null,
      refreshOnCreate: false,
    });
    const exactModel = modelRuntime.getModel(request.model.provider, request.model.id);
    const registered = exactModel || modelRuntime.getModels(request.model.provider)[0];
    if (!registered) throw new Error(`Unknown Pi model ${request.model.provider}/${request.model.id}`);
    const model = {
      ...registered,
      id: request.model.id,
      name: request.model.id,
      api: request.model.api,
      baseUrl: request.model.base_url,
      reasoning: exactModel ? registered.reasoning : request.model.reasoning,
      thinkingLevelMap:
        exactModel || !request.model.id.toLowerCase().includes("deepseek-v4")
          ? registered.thinkingLevelMap
          : {
              minimal: null,
              low: request.model.id.toLowerCase().includes("flash") ? "low" : null,
              medium: null,
              high: "high",
              xhigh: null,
              max: "max",
            },
      samplingParams: { ...registered.samplingParams, top_p: request.model.top_p },
      cost: Object.keys(request.model.cost || {}).length > 0 ? request.model.cost : registered.cost,
    };

    const settingsManager = SettingsManager.inMemory({
      compaction: { enabled: false },
      retry: { enabled: false, maxRetries: 0, provider: { maxRetries: 0 } },
    });
    const tools = customTools(request.tools, protocol);
    const runtimeCwd = process.cwd();
    ({ session } = await createAgentSession({
      cwd: runtimeCwd,
      agentDir: runtimeCwd,
      model,
      thinkingLevel: model.reasoning ? request.model.thinking_level : "off",
      modelRuntime,
      resourceLoader: resourceLoader(request.system_prompt),
      noTools: "builtin",
      tools: tools.map((tool) => tool.name),
      customTools: tools,
      sessionManager: SessionManager.inMemory(runtimeCwd),
      settingsManager,
    }));

    const meter = usageAccumulator();
    let turns = 0;
    let lastStopReason = "stop";
    session.subscribe((event) => {
      if (event.type !== "message_end" || event.message?.role !== "assistant") return;
      turns += 1;
      lastStopReason = event.message.stopReason || lastStopReason;
      send({ type: "trajectory", step: turns, ...trajectoryMessage(event.message) });
    });

    const originalStream = session.agent.streamFunction;
    session.agent.streamFunction = meteredStream(originalStream, protocol, request, meter);
    let enforcedStopReason;
    session.agent.shouldStopAfterTurn = () => {
      if (turns >= request.max_turns) enforcedStopReason = "max_steps";
      else if (
        request.assignment.budget_usd > 0 &&
        meter.totals.cost_usd >= request.assignment.budget_usd * 0.9
      ) {
        enforcedStopReason = "budget_exhausted";
      }
      return enforcedStopReason !== undefined;
    };

    await session.prompt(request.user_message, { expandPromptTemplates: false });
    if (meter.error) throw meter.error;
    if (lastStopReason === "error" || lastStopReason === "aborted") {
      throw new Error(`CyberPi model stopped with reason: ${lastStopReason}`);
    }
    send({
      type: "complete",
      stop_reason: enforcedStopReason || lastStopReason,
      turns,
      model_calls: meter.calls,
    });
  } finally {
    session?.dispose();
    protocol.input.close();
  }
}

run().catch((error) => {
  fail(error);
  process.exitCode = 1;
});
