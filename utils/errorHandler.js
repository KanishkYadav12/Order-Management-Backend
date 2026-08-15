/**
 * Application error types.
 *
 * Every error carries an HTTP `statusCode` and a stable machine-readable `code`,
 * so the error middleware never has to guess and clients can branch on `code`
 * rather than on message text.
 *
 * ── Call signatures ────────────────────────────────────────────────────────
 * The canonical form is:
 *
 *     new ClientError("Table not found", 404, "TABLE_NOT_FOUND")
 *
 * Two legacy shapes are still in use across the codebase and are normalised
 * automatically so the sweep can happen incrementally:
 *
 *     new ClientError("Table not found", 404)     // status in slot 2
 *     new ClientError("NotFoundError", "Table not found")  // name/message inverted
 *
 * The inverted form is detected by testing slot 1 against LEGACY_NAMES.
 */

/** Legacy error names that used to be passed as the FIRST argument. */
const LEGACY_STATUS_BY_NAME = {
  ValidationError: 400,
  Required: 400,
  InvalidDevKey: 400,
  BadRequest: 400,
  AuthError: 401,
  Unauthorized: 401,
  ApprovalError: 403,
  ForbiddenError: 403,
  Forbidden: 403,
  NotFoundError: 404,
  NotFound: 404,
  ConflictError: 409,
  Conflict: 409,
};

const LEGACY_NAME_PATTERN = /^[A-Za-z]+(Error|Key)$/;

const isLegacyName = (value) =>
  typeof value === "string" &&
  (Object.hasOwn(LEGACY_STATUS_BY_NAME, value) || LEGACY_NAME_PATTERN.test(value));

/**
 * Normalises the three accepted call shapes into { message, statusCode, code }.
 */
const normaliseArgs = (a, b, c, defaultStatus) => {
  // new XError("NotFoundError", "Table not found")  → inverted legacy form.
  // Only treat it as inverted when slot 2 is a message-like string, otherwise
  // a genuine message that happens to look like a name would be swallowed.
  if (isLegacyName(a) && typeof b === "string") {
    return {
      message: b,
      statusCode: LEGACY_STATUS_BY_NAME[a] ?? defaultStatus,
      code: toCode(a),
    };
  }

  // new XError("Table not found", 404)
  if (typeof b === "number") {
    return { message: a, statusCode: b, code: c ? toCode(c) : undefined };
  }

  // new XError("Table not found", "NotFoundError")  → name in slot 2
  if (typeof b === "string") {
    return {
      message: a,
      statusCode: LEGACY_STATUS_BY_NAME[b] ?? defaultStatus,
      code: toCode(b),
    };
  }

  // new XError("Table not found")
  return { message: a, statusCode: defaultStatus, code: undefined };
};

/** "NotFoundError" → "NOT_FOUND_ERROR" */
const toCode = (name) =>
  String(name)
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toUpperCase();

/**
 * Base class for every error the application raises deliberately.
 * `isOperational` marks it as expected — the error middleware surfaces the
 * message to the client. Unexpected errors are masked instead.
 */
export class AppError extends Error {
  constructor(message, statusCode = 500, code = "INTERNAL_ERROR") {
    super(typeof message === "string" ? message : "Unexpected error");
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * A 4xx: the caller did something wrong. Message is safe to show the client.
 */
export class ClientError extends AppError {
  constructor(a, b, c) {
    const { message, statusCode, code } = normaliseArgs(a, b, c, 400);
    super(message, statusCode, code ?? "CLIENT_ERROR");
    this.type = "ClientError";
  }
}

/**
 * A 5xx: something failed on our side. The message is logged in full but
 * replaced with a generic string before it reaches the client.
 */
export class ServerError extends AppError {
  constructor(a, b, c) {
    const { message, statusCode, code } = normaliseArgs(a, b, c, 500);
    super(message, statusCode, code ?? "SERVER_ERROR");
    this.type = "ServerError";
  }
}

/* ── Preferred, explicit subclasses ─────────────────────────────────────── */

export class ValidationError extends ClientError {
  constructor(message = "Request validation failed", details) {
    super(message, 400, "VALIDATION_ERROR");
    /** Field-level issues, shaped by the Zod validate() middleware. */
    this.details = details;
  }
}

export class AuthError extends ClientError {
  constructor(message = "Authentication required") {
    super(message, 401, "UNAUTHENTICATED");
  }
}

export class ForbiddenError extends ClientError {
  constructor(message = "You do not have access to this resource") {
    super(message, 403, "FORBIDDEN");
  }
}

export class NotFoundError extends ClientError {
  constructor(resource = "Resource") {
    super(`${resource} not found`, 404, "NOT_FOUND");
  }
}

export class ConflictError extends ClientError {
  constructor(message = "Resource already exists") {
    super(message, 409, "CONFLICT");
  }
}

export class RateLimitError extends ClientError {
  constructor(message = "Too many requests, please try again later") {
    super(message, 429, "RATE_LIMITED");
  }
}
