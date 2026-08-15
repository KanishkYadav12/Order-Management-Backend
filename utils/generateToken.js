import jwt from "jsonwebtoken";
import crypto from "crypto";
import env from "../config/env.js";

/**
 * Token issuing and verification.
 *
 * Three distinct token kinds, each with its own secret so a leak of one
 * cannot be replayed as another:
 *
 *   access    short-lived (15m), sent as `Authorization: Bearer`
 *   refresh   long-lived (30d), sent as an httpOnly cookie, rotated on use
 *   customer  per-table QR session (4h), sent as `X-Customer-Session`
 *
 * Every token carries `typ` and the verifier asserts it, so an access token
 * can never be presented where a refresh token is expected.
 */

const ISSUER = "oms-api";

/* ── Access ───────────────────────────────────────────────────────────── */

export const generateAccessToken = (userId, role, hotelId) =>
  jwt.sign(
    {
      sub: userId.toString(),
      role,
      hotelId: hotelId ? hotelId.toString() : null,
      typ: "access",
    },
    env.ACCESS_TOKEN_SECRET,
    { expiresIn: env.ACCESS_TOKEN_EXPIRES, issuer: ISSUER }
  );

export const verifyAccessToken = (token) => {
  const payload = jwt.verify(token, env.ACCESS_TOKEN_SECRET, {
    issuer: ISSUER,
  });
  if (payload.typ !== "access") {
    throw new jwt.JsonWebTokenError("Wrong token type");
  }
  return payload;
};

/* ── Refresh ──────────────────────────────────────────────────────────── */

/**
 * Refresh tokens carry a random `jti`. Storing a hash of the jti against the
 * user lets a specific session be revoked, and lets reuse of an already-rotated
 * token be detected (the signal that a token was stolen).
 */
export const generateRefreshToken = (userId, role) => {
  const tokenId = crypto.randomUUID();
  const token = jwt.sign(
    { sub: userId.toString(), role, jti: tokenId, typ: "refresh" },
    env.REFRESH_TOKEN_SECRET,
    { expiresIn: env.REFRESH_TOKEN_EXPIRES, issuer: ISSUER }
  );
  return { token, tokenId };
};

export const verifyRefreshToken = (token) => {
  const payload = jwt.verify(token, env.REFRESH_TOKEN_SECRET, {
    issuer: ISSUER,
  });
  if (payload.typ !== "refresh") {
    throw new jwt.JsonWebTokenError("Wrong token type");
  }
  return payload;
};

/** Refresh tokens are stored hashed, never in the clear. */
export const hashToken = (value) =>
  crypto.createHash("sha256").update(value).digest("hex");

/* ── Customer (QR table session) ──────────────────────────────────────── */

/**
 * Binds an anonymous diner to one table for one sitting.
 *
 * Without this, the customer order endpoints had to be fully public — which
 * let anyone create orders on any table in any restaurant, and read any
 * order by id.
 */
export const generateCustomerSession = ({ tableId, hotelId, customerId }) => {
  const sessionId = crypto.randomUUID();
  const token = jwt.sign(
    {
      sessionId,
      tableId: tableId.toString(),
      hotelId: hotelId.toString(),
      customerId: customerId ? customerId.toString() : null,
      typ: "customer",
    },
    env.CUSTOMER_SESSION_SECRET,
    { expiresIn: env.CUSTOMER_SESSION_EXPIRES, issuer: ISSUER }
  );
  return { token, sessionId };
};

export const verifyCustomerSession = (token) => {
  const payload = jwt.verify(token, env.CUSTOMER_SESSION_SECRET, {
    issuer: ISSUER,
  });
  if (payload.typ !== "customer") {
    throw new jwt.JsonWebTokenError("Wrong token type");
  }
  return payload;
};

/* ── Cookie options for the refresh token ─────────────────────────────── */

export const refreshCookieName = "oms_refresh";

export const refreshCookieOptions = () => ({
  httpOnly: true,
  secure: env.isProduction,
  // The dashboard is served from a different origin than the API, so the
  // cookie has to be readable cross-site — which requires SameSite=None,
  // which in turn requires Secure. In local dev over http we fall back to
  // Lax, where same-origin dev servers still work.
  sameSite: env.isProduction ? "none" : "lax",
  path: "/api/v1/auth",
  maxAge: 30 * 24 * 60 * 60 * 1000,
});

/**
 * @deprecated Use generateAccessToken. Retained so any call site not yet
 * migrated keeps working during the auth rewrite.
 */
export const generatetoken = (userId, role, hotelId) =>
  generateAccessToken(userId, role, hotelId);
