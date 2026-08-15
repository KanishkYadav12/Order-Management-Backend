import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import { RateLimitError } from "../utils/errorHandler.js";
import logger from "../utils/logger.js";

/**
 * Normalises a client IP into a limiter key.
 *
 * A raw IPv6 address is a /128, and a single attacker routinely controls a
 * whole /64 — keying on the full address would let them cycle through
 * effectively unlimited keys. `ipKeyGenerator` collapses IPv6 to its subnet
 * while leaving IPv4 addresses untouched.
 */
const clientKey = (req) => ipKeyGenerator(req.ip);

/** Lowercased email from the body or params, for per-account limiting. */
const emailKey = (req) =>
  String(req.body?.email ?? req.params?.email ?? "")
    .toLowerCase()
    .trim();

/**
 * Builds a rate limiter that reports through the app's normal error pipeline,
 * so a throttled request looks like every other failure to the client.
 *
 * @param {object}   options
 * @param {number}   options.windowMs   Window length in milliseconds.
 * @param {number}   options.limit      Requests permitted per window.
 * @param {string}   options.message    Client-facing message.
 * @param {Function} [options.keyGenerator] Defaults to per-IP.
 */
const buildLimiter = ({ windowMs, limit, message, keyGenerator }) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    ...(keyGenerator ? { keyGenerator } : {}),
    handler: (req, _res, next) => {
      logger.warn(
        { path: req.originalUrl, ip: req.ip, method: req.method },
        "rate limit exceeded"
      );
      next(new RateLimitError(message));
    },
  });

/** Baseline ceiling for the whole API. Generous — this is a backstop. */
export const globalLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 600,
  message: "Too many requests. Please slow down and try again shortly.",
});

/**
 * Credential endpoints. Keyed on IP + submitted email so one attacker cannot
 * lock out every user from a shared NAT, and so rotating IPs still can't
 * brute-force a single account quickly.
 */
export const authLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: "Too many attempts. Please wait 15 minutes and try again.",
  keyGenerator: (req) => `${clientKey(req)}:${emailKey(req)}`,
});

/** OTP verification — the code space is small, so this is the real defence. */
export const otpLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  message: "Too many verification attempts. Please request a new code.",
  keyGenerator: (req) => `${clientKey(req)}:${emailKey(req)}`,
});

/** Anything that sends an email, to stop the SMTP account being used as a relay. */
export const emailLimiter = buildLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  message: "Too many emails requested. Please try again in an hour.",
  keyGenerator: (req) => `${clientKey(req)}:${emailKey(req)}`,
});

/**
 * Customer ordering from a QR table. Keyed per table so a flood against one
 * table cannot stop the rest of the restaurant taking orders.
 */
export const customerOrderLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 40,
  message: "Too many orders from this table. Please ask a member of staff.",
  keyGenerator: (req) =>
    req.params?.tableId ? `table:${req.params.tableId}` : clientKey(req),
});

/** Uploads are expensive and billed per byte. */
export const uploadLimiter = buildLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 60,
  message: "Upload limit reached. Please try again later.",
  keyGenerator: (req) => req.user?._id?.toString() ?? clientKey(req),
});

/** AI endpoints call a paid API — throttle per authenticated hotel. */
export const aiLimiter = buildLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 100,
  message: "AI request limit reached for this hour. Please try again later.",
  keyGenerator: (req) => req.user?.hotelId?.toString() ?? clientKey(req),
});
