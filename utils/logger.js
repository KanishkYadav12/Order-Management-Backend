import pino from "pino";

const isProduction = process.env.NODE_ENV === "production";

/**
 * Fields that must never reach the log sink, at any nesting depth handled by
 * pino's redaction paths. Extend this list rather than trimming log payloads
 * at the call site.
 */
const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  "req.body.password",
  "req.body.newPassword",
  "req.body.currentPassword",
  "req.body.confirmPassword",
  "req.body.otp",
  "req.body.devKey",
  "req.body.token",
  "res.headers['set-cookie']",
  "password",
  "token",
  "accessToken",
  "refreshToken",
  "otp",
  "otpDetails",
  "devKey",
  "*.password",
  "*.token",
  "*.otp",
];

const logger = pino({
  level: process.env.LOG_LEVEL || (isProduction ? "info" : "debug"),
  redact: { paths: REDACT_PATHS, censor: "[redacted]" },
  base: { service: "oms-api" },
  formatters: {
    level: (label) => ({ level: label }),
  },
  // Pretty output locally; newline-delimited JSON in production so the
  // platform's log aggregator can parse it.
  transport: isProduction
    ? undefined
    : {
        target: "pino-pretty",
        options: { colorize: true, translateTime: "HH:MM:ss", ignore: "pid,hostname,service" },
      },
});

export default logger;
