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
    defaultModel: "gemini-2.0-flash",
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

const callGemini = async ({ system, prompt, maxTokens, json }) => {
  const model = env.AI_MODEL || PROVIDERS.gemini.defaultModel;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${env.AI_API_KEY}`;

  const response = await withTimeout(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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
    logger.error({ status: response.status, body }, "Gemini request failed");
    throw unavailable(response.status === 429 ? "The free quota is used up for now." : "");
  }

  const data = await response.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
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
