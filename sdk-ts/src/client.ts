export type Decision =
  | "allow"
  | "warn"
  | "require_approval"
  | "block"
  | "allow_with_redaction"
  | "step_up_auth"
  | "require_jit_credential"
  | "contain";

export type Authorization = {
  token: string;
  authorization_id?: string;
  authorizationId?: string;
  expires_at?: string;
  expiresAt?: string;
  approved_parameter_digest?: string;
  parameter_digest?: string;
  parameterDigest?: string;
  digest?: string;
};

export type GateResponse = {
  decision: Decision;
  consulted: boolean;
  reason?: string;
  incident_id?: string;
  request_id?: string;
  enforced?: boolean;
  authorization?: Authorization | null;
};

export type ExecuteResult = {
  tool: string;
  result: unknown;
  protect: GateResponse;
  receipt?: Record<string, unknown>;
  capability?: Record<string, unknown>;
};

export class SentinelUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SentinelUnavailable";
  }
}

const DECISIONS = new Set<Decision>([
  "allow",
  "warn",
  "require_approval",
  "block",
  "allow_with_redaction",
  "step_up_auth",
  "require_jit_credential",
  "contain",
]);

const PROCEEDS = new Set<Decision>(["allow", "warn", "allow_with_redaction"]);

export function stopsAction(decision: Decision): boolean {
  return !PROCEEDS.has(decision);
}

function parseGateResponse(raw: unknown): GateResponse {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SentinelUnavailable("Sentinel returned a non-object response");
  }
  const body = raw as Record<string, unknown>;
  const decision = String(body.decision ?? body.outcome ?? "").trim() as Decision;
  if (!DECISIONS.has(decision)) {
    throw new SentinelUnavailable(`unknown Sentinel decision ${JSON.stringify(decision)}`);
  }
  const authorization = body.authorization as Authorization | null | undefined;
  if (authorization !== null && authorization !== undefined) {
    if (typeof authorization !== "object" || Array.isArray(authorization)) {
      throw new SentinelUnavailable("authorization is not an object");
    }
    if (typeof authorization.token !== "string" || authorization.token.trim() === "") {
      throw new SentinelUnavailable("authorization has no token");
    }
  }
  return {
    decision,
    consulted: true,
    reason: String(body.reason ?? ""),
    incident_id: String(body.incident_id ?? body.incidentId ?? ""),
    request_id: String(body.request_id ?? body.requestId ?? ""),
    enforced: Boolean(body.enforced ?? false),
    authorization: authorization ?? null,
  };
}

async function parseJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch (error) {
    throw new SentinelUnavailable(`Sentinel response was not JSON: ${error}`);
  }
}

export class SentinelClient {
  readonly baseUrl: string;
  readonly apiKey: string;

  constructor(options: { baseUrl: string; apiKey: string }) {
    const url = new URL(options.baseUrl);
    if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
      throw new Error("plain HTTP is only allowed for loopback development");
    }
    if (options.apiKey.trim() === "") {
      throw new Error("apiKey is required");
    }
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
  }

  async check(input: {
    agentId: string;
    action?: string;
    resource?: string;
    tool?: string;
    arguments?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
  }): Promise<GateResponse> {
    const metadata = { ...(input.metadata ?? {}) };
    if (input.tool) metadata.tool = input.tool;
    if (input.arguments) metadata.arguments = input.arguments;
    const body = {
      agentId: input.agentId,
      eventType: "tool_call",
      action: input.action ?? input.tool ?? "",
      resource: input.resource ?? "",
      metadata,
    };
    const response = await fetch(`${this.baseUrl}/v1/protect/evaluate`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (response.status !== 200 && response.status !== 403) {
      throw new SentinelUnavailable(`Sentinel answered HTTP ${response.status}`);
    }
    return parseGateResponse(await parseJson(response));
  }

  async execute(input: {
    agentId: string;
    tool: string;
    action?: string;
    resource?: string;
    arguments?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
    trustLevel?: string;
    authorization?: Authorization | string | null;
  }): Promise<ExecuteResult> {
    const token =
      typeof input.authorization === "string"
        ? input.authorization
        : input.authorization?.token ?? "";
    const body: Record<string, unknown> = {
      agentId: input.agentId,
      tool: input.tool,
      trustLevel: input.trustLevel ?? "unsigned",
      arguments: input.arguments ?? {},
      resource: input.resource ?? "",
      action: input.action ?? input.tool,
      metadata: input.metadata ?? {},
    };
    if (token) body.authorization = { token };
    const response = await fetch(`${this.baseUrl}/v1/tools/execute`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(body),
    });
    if (response.status < 200 || response.status >= 300) {
      throw new SentinelUnavailable(`Sentinel answered HTTP ${response.status}`);
    }
    const payload = await parseJson(response);
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
      throw new SentinelUnavailable("execute returned a non-object response");
    }
    const result = payload as Record<string, unknown>;
    return {
      tool: String(result.tool ?? input.tool),
      result: result.result,
      protect: parseGateResponse(result.protect),
      receipt: result.receipt as Record<string, unknown> | undefined,
      capability: result.capability as Record<string, unknown> | undefined,
    };
  }

  private headers(): Record<string, string> {
    return {
      "content-type": "application/json",
      accept: "application/json",
      authorization: `Bearer ${this.apiKey}`,
    };
  }
}
