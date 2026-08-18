import env from "../../config/env.js";
import logger from "../../utils/logger.js";
import { ClientError } from "../../utils/errorHandler.js";

/**
 * Pluggable language-model adapter.
 *
 * Built on `fetch` rather than a vendor SDK so the restaurant can point this
 * at whichever provider they can get for free, and switch without a code
 * change or a new dependency:
 *
 *   gemini  Google AI Studio — generous free tier, no card required
 *   groq    Groq Cloud — free tier, very fast
 *   ollama  A model running on your own machine or server — free, private,
 *           no rate limit, works with no internet
 *   none    Disabled. Every analytic feature still works; only the
 *           conversational layer is switched off.
 *
 * Nothing in this file is required for the numbers — `menuIntelligence.js`
 * computes those deterministically. The model only turns figures into prose
 * and maps a plain-English question onto a report, so a small free model is
 * entirely adequate here.
 */

const PROVIDERS = {
  gemini: {
    label: "Google Gemini",
    freeTier: true,
    defaultModel: "gemini-3.5-flash",
    envKey: "GEMINI_API_KEY",
    signupUrl: "https://aistudio.google.com/apikey",
  },
  groq: {
    label: "Groq",
    freeTier: true,
    defaultModel: "llama-3.3-70b-versatile",
    envKey: "GROQ_API_KEY",
    signupUrl: "https://console.groq.com/keys",
  },
  ollama: {
    label: "Ollama (self-hosted)",
    freeTier: true,
    defaultModel: "llama3.1",
    envKey: null, // runs locally, no key
    signupUrl: "https://ollama.com/download",
  },
};

export const providerInfo = () => {
  const name = env.AI_PROVIDER;
  return {
    provider: name,
    ...(PROVIDERS[name] ?? {}),
    enabled: isEnabled(),
  };
};

export const isEnabled = () => {
  const name = env.AI_PROVIDER;
  if (name === "none" || !PROVIDERS[name]) return false;
  if (name === "ollama") return Boolean(env.OLLAMA_URL);
  return Boolean(env.AI_API_KEY);
};

/** Uniform error so callers don't have to know which provider failed. */
const unavailable = (detail) =>
  new ClientError(
    `The assistant is unavailable right now. ${detail ?? ""}`.trim(),
    503,
    "AI_UNAVAILABLE"
  );

/**
 * A spent quota is the caller's business, not a server fault.
 *
 * Reported as 503 it became "Something went wrong on our end" — the error
 * middleware masks every 5xx message, because 5xx text routinely carries
 * driver internals. So the one piece of information that actually helps ("the
 * free allowance is used up, wait a minute") was stripped on its way out. 429
 * is both the honest status and below the masking threshold, so the real
 * message survives to the screen.
 */
const quotaSpent = () =>
  new ClientError(
    "The AI free quota is used up for now. It resets shortly — try again in a minute.",
    429,
    "AI_QUOTA_EXHAUSTED"
  );

/**
 * Models to fall back to when the configured one is rate-limited.
 *
 * Gemini meters per model as well as per project, so one model returning 429
 * while its siblings are fine is the normal free-tier experience rather than
 * an edge case. Falling back keeps the feature alive instead of failing the
 * whole request over a single busy endpoint.
 */
const GEMINI_FALLBACKS = [
  "gemini-3.5-flash-lite",
  "gemini-3-flash-preview",
  "gemini-3.1-flash-lite",
];

/** The configured model first, then any fallback not already tried. */
const geminiModelChain = () => {
  const configured = env.AI_MODEL || PROVIDERS.gemini.defaultModel;
  return [configured, ...GEMINI_FALLBACKS.filter((m) => m !== configured)];
};

const withTimeout = async (url, options, ms = 30_000) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
};

/* ── Per-provider request shapes ──────────────────────────────────────── */

const callGeminiOnce = async ({ system, prompt, maxTokens, json, model }) => {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  const response = await withTimeout(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // Header, not `?key=` — a query string ends up in proxy and access logs.
      "x-goog-api-key": env.AI_API_KEY,
    },
    body: JSON.stringify({
      systemInstruction: system ? { parts: [{ text: system }] } : undefined,
      contents: [{ role: "user", parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: maxTokens,
        temperature: 0.2,
        ...(json ? { responseMimeType: "application/json" } : {}),
      },
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    logger.warn({ status: response.status, model, body: body.slice(0, 300) }, "Gemini request failed");
    // Surfaced to the retry loop, which decides whether another model helps.
    const error = response.status === 429 ? quotaSpent() : unavailable();
    error.rateLimited = response.status === 429;
    throw error;
  }

  const data = await response.json();

  /**
   * Join every text part, do not take the first.
   *
   * Reasoning models return more than one part — a thought signature travels
   * alongside the answer, and longer replies arrive split. Reading `parts[0]`
   * silently truncated JSON responses to their opening fragment, which then
   * failed to parse and surfaced as "the assistant is unavailable".
   */
  const candidate = data?.candidates?.[0];
  const text = (candidate?.content?.parts ?? [])
    .map((part) => part.text ?? "")
    .join("");

  if (candidate?.finishReason === "MAX_TOKENS") {
    logger.warn(
      { model, chars: text.length },
      "Gemini hit the output cap — raise maxTokens"
    );
  }

  return text;
};

/** Walks the model chain, moving on only when a model is rate-limited. */
const callGemini = async (params) => {
  const chain = geminiModelChain();
  let lastError;

  for (const model of chain) {
    try {
      return await callGeminiOnce({ ...params, model });
    } catch (err) {
      lastError = err;
      // Anything other than a quota block will fail the same way on a sibling
      // model, so there is nothing to gain by trying one.
      if (!err.rateLimited) throw err;
      logger.info({ model }, "model rate-limited, trying the next one");
    }
  }

  throw lastError ?? quotaSpent();
};

const callGroq = async ({ system, prompt, maxTokens, json }) => {
  const model = env.AI_MODEL || PROVIDERS.groq.defaultModel;

  const response = await withTimeout(
    "https://api.groq.com/openai/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${env.AI_API_KEY}`,
      },
      body: JSON.stringify({
        model,
        max_tokens: maxTokens,
        temperature: 0.2,
        ...(json ? { response_format: { type: "json_object" } } : {}),
        messages: [
          ...(system ? [{ role: "system", content: system }] : []),
          { role: "user", content: prompt },
        ],
      }),
    }
  );

  if (!response.ok) {
    const body = await response.text();
    logger.error({ status: response.status, body }, "Groq request failed");
    throw unavailable(response.status === 429 ? "The free quota is used up for now." : "");
  }

  const data = await response.json();
  return data?.choices?.[0]?.message?.content ?? "";
};

const callOllama = async ({ system, prompt, maxTokens, json }) => {
  const model = env.AI_MODEL || PROVIDERS.ollama.defaultModel;
  const base = env.OLLAMA_URL.replace(/\/$/, "");

  const response = await withTimeout(
    `${base}/api/chat`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model,
        stream: false,
        ...(json ? { format: "json" } : {}),
        options: { temperature: 0.2, num_predict: maxTokens },
        messages: [
          ...(system ? [{ role: "system", content: system }] : []),
          { role: "user", content: prompt },
        ],
      }),
    },
    // A local model on modest hardware is slower than a hosted one.
    120_000
  );

  if (!response.ok) {
    logger.error({ status: response.status }, "Ollama request failed");
    throw unavailable("Check that Ollama is running.");
  }

  const data = await response.json();
  return data?.message?.content ?? "";
};

const ADAPTERS = { gemini: callGemini, groq: callGroq, ollama: callOllama };

/**
 * Sends one prompt and returns the text.
 *
 * @param {object} params
 * @param {string} params.prompt
 * @param {string} [params.system]
 * @param {number} [params.maxTokens]
 * @param {boolean} [params.json] Ask the provider for JSON output.
 */
export const complete = async ({ system, prompt, maxTokens = 1200, json = false }) => {
  if (!isEnabled()) {
    throw unavailable(
      "No AI provider is configured. Set AI_PROVIDER and AI_API_KEY to switch it on."
    );
  }

  const adapter = ADAPTERS[env.AI_PROVIDER];
  if (!adapter) throw unavailable(`Unknown provider '${env.AI_PROVIDER}'.`);

  const started = Date.now();
  try {
    const text = await adapter({ system, prompt, maxTokens, json });
    logger.info(
      { provider: env.AI_PROVIDER, ms: Date.now() - started },
      "ai completion"
    );
    return text.trim();
  } catch (err) {
    if (err.name === "AbortError") throw unavailable("The request timed out.");
    throw err;
  }
};

/** Parses a JSON completion, tolerating models that wrap it in a code fence. */
export const completeJson = async (params) => {
  const raw = await complete({ ...params, json: true });
  const cleaned = raw
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```\s*$/, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    // Last resort: pull the outermost object out of surrounding prose.
    const match = cleaned.match(/\{[\s\S]*\}/);
    if (match) {
      try {
        return JSON.parse(match[0]);
      } catch {
        /* fall through */
      }
    }
    logger.warn({ raw: cleaned.slice(0, 400) }, "could not parse AI JSON");
    throw unavailable("The assistant returned something unreadable.");
  }
};

export { PROVIDERS };

/* ── Multi-turn chat with tools ───────────────────────────────────────── */

/**
 * A conversational turn that may call tools.
 *
 * Kept separate from `complete()` because the shapes genuinely differ: this
 * one carries history, declares callable functions, and can return a *request
 * to call one* instead of prose. Squeezing both through one signature would
 * make the common single-shot case harder to read for no gain.
 *
 * Gemini only for now. Groq speaks the OpenAI tool dialect and Ollama's tool
 * support varies by model, so rather than pretend, the others fall back to a
 * plain completion and simply never ask for a tool.
 *
 * @returns {{text: string, toolCalls: Array<{name: string, args: object}>}}
 */
export const chatWithTools = async ({
  system,
  messages,
  tools = [],
  maxTokens = 1400,
  temperature = 0.4,
}) => {
  if (!isEnabled()) throw unavailable("No AI provider is configured.");

  if (env.AI_PROVIDER !== "gemini") {
    // Degrade honestly: answer from the context already in the prompt.
    const last = [...messages].reverse().find((m) => m.role === "user");
    const text = await complete({
      system,
      prompt: last?.parts?.map((p) => p.text).join("\n") ?? "",
      maxTokens,
    });
    return { text, toolCalls: [] };
  }

  // Same fallback chain as `complete()`: a single rate-limited model must not
  // take the whole conversation down when its siblings are answering.
  let response;
  let data;

  for (const model of geminiModelChain()) {
    response = await withTimeout(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-goog-api-key": env.AI_API_KEY,
        },
        body: JSON.stringify({
          systemInstruction: system ? { parts: [{ text: system }] } : undefined,
          contents: messages,
          ...(tools.length > 0
            ? { tools: [{ functionDeclarations: tools }] }
            : {}),
          generationConfig: { maxOutputTokens: maxTokens, temperature },
        }),
      },
      45_000
    );

    if (response.ok) {
      data = await response.json();
      break;
    }

    const body = await response.text();
    logger.warn(
      { status: response.status, model, body: body.slice(0, 300) },
      "Gemini chat failed"
    );

    // Only a quota block is worth retrying elsewhere; a malformed request
    // fails identically on every model.
    if (response.status !== 429) throw unavailable();
    logger.info({ model }, "chat model rate-limited, trying the next one");
  }

  if (!data) throw quotaSpent();
  const parts = data?.candidates?.[0]?.content?.parts ?? [];

  return {
    text: parts
      .map((part) => part.text ?? "")
      .join("")
      .trim(),
    toolCalls: parts
      .filter((part) => part.functionCall)
      .map((part) => ({
        name: part.functionCall.name,
        args: part.functionCall.args ?? {},
      })),
    // Gemini 3 returns an opaque signature that must be echoed back with the
    // model's own turn, or the follow-up request is rejected.
    raw: data?.candidates?.[0]?.content ?? null,
  };
};
