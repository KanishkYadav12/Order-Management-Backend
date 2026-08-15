import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

/**
 * Environment contract.
 *
 * The process refuses to boot if anything required is missing or malformed —
 * a misconfigured deploy should fail loudly at startup rather than surface as
 * a 500 on the first request that happens to need the variable.
 */
const csv = (fallback = []) =>
  z
    .string()
    .optional()
    .transform((value) =>
      value
        ? value
            .split(",")
            .map((entry) => entry.trim())
            .filter(Boolean)
        : fallback
    );

const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  PORT: z.coerce.number().int().positive().default(5000),
  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace"])
    .optional(),

  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  DATABASE_NAME: z.string().default("HotelOrderManagementSystem"),

  // Secrets. 32 chars is the floor for an HS256 signing key.
  ACCESS_TOKEN_SECRET: z
    .string()
    .min(32, "ACCESS_TOKEN_SECRET must be at least 32 characters"),
  ACCESS_TOKEN_EXPIRES: z.string().default("15m"),
  REFRESH_TOKEN_SECRET: z
    .string()
    .min(32, "REFRESH_TOKEN_SECRET must be at least 32 characters"),
  REFRESH_TOKEN_EXPIRES: z.string().default("30d"),
  CUSTOMER_SESSION_SECRET: z
    .string()
    .min(32, "CUSTOMER_SESSION_SECRET must be at least 32 characters"),
  CUSTOMER_SESSION_EXPIRES: z.string().default("4h"),

  // Where the owner dashboard lives — used for password-reset links.
  FRONTEND_URL: z.string().min(1, "FRONTEND_URL is required"),
  // Where the QR customer menu lives — used when generating table QR codes.
  CUSTOMER_APP_URL: z.string().min(1, "CUSTOMER_APP_URL is required"),
  /** Extra browser origins allowed through CORS, comma-separated. */
  CORS_ORIGINS: csv([]),

  EMAIL_HOST: z.string().min(1),
  EMAIL_PORT: z.coerce.number().int().positive().default(587),
  EMAIL_USER: z.string().min(1),
  EMAIL_PASS: z.string().min(1),
  EMAIL_FROM: z.string().min(1),

  ABLY_API_KEY: z.string().min(1, "ABLY_API_KEY is required"),

  CLOUDINARY_CLOUD_NAME: z.string().optional(),
  CLOUDINARY_API_KEY: z.string().optional(),
  CLOUDINARY_API_SECRET: z.string().optional(),

  /* ── AI ────────────────────────────────────────────────────────────────
     The analytics (menu engineering, forecasting, basket analysis) are pure
     maths and always run. These settings only power the conversational
     layer, and every supported provider has a free tier. */
  AI_PROVIDER: z.enum(["none", "gemini", "groq", "ollama"]).default("none"),
  /** Not needed for `ollama`, which runs on your own machine. */
  AI_API_KEY: z.string().optional(),
  /** Overrides the provider's default model. */
  AI_MODEL: z.string().optional(),
  OLLAMA_URL: z.string().default("http://localhost:11434"),
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues
    .map((issue) => `  • ${issue.path.join(".") || "(root)"}: ${issue.message}`)
    .join("\n");

  // Deliberately console.error rather than the logger: the logger itself
  // reads config, and this must work even if nothing else does.
  console.error(
    `\nInvalid environment configuration — refusing to start.\n\n${issues}\n\n` +
      `Copy .env.example to .env and fill in the missing values.\n`
  );
  process.exit(1);
}

const env = Object.freeze({
  ...parsed.data,
  isProduction: parsed.data.NODE_ENV === "production",
  isDevelopment: parsed.data.NODE_ENV === "development",
  /**
   * True when the conversational assistant can run. The analytics endpoints
   * ignore this — they need no provider at all.
   */
  aiEnabled:
    parsed.data.AI_PROVIDER !== "none" &&
    (parsed.data.AI_PROVIDER === "ollama"
      ? Boolean(parsed.data.OLLAMA_URL)
      : Boolean(parsed.data.AI_API_KEY)),
});

export default env;
