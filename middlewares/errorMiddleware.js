import { randomUUID } from "crypto";
import { AppError } from "../utils/errorHandler.js";
import logger from "../utils/logger.js";

const isProduction = () => process.env.NODE_ENV === "production";

/**
 * Translates framework/driver errors into the shape the app uses.
 * Returns null when the error is not one of the known third-party kinds.
 */
const translateKnownError = (err) => {
  /**
   * Mongo duplicate key.
   *
   * The naive message named the first key in the index, which on a compound
   * index is usually the *scope* rather than the thing that clashed — a
   * collision on `{hotelId, invoiceNumber}` read as "That hotelId is already
   * in use", which is both meaningless to the user and wrong about the cause.
   * Prefer a field the person actually typed, and fall back to something
   * honest rather than something confidently incorrect.
   */
  if (err.code === 11000) {
    const LABELS = {
      email: "email address",
      name: "name",
      sequence: "table number",
      invoiceNumber: "invoice number",
      key: "key",
    };
    // Scope fields identify which tenant the row belongs to; they are never
    // what the user duplicated.
    const SCOPE = new Set(["hotelId", "_id"]);

    const keys = Object.keys(err.keyValue ?? {});
    const culprit = keys.find((key) => !SCOPE.has(key));

    return {
      statusCode: 409,
      code: "DUPLICATE_KEY",
      message: culprit
        ? `That ${LABELS[culprit] ?? culprit} is already in use.`
        : "That already exists.",
    };
  }

  switch (err.name) {
    // Mongoose: malformed ObjectId etc.
    case "CastError":
      return {
        statusCode: 400,
        code: "INVALID_ID",
        message: `'${err.path}' is not a valid value.`,
      };

    // Mongoose schema validation
    case "ValidationError":
      if (err.errors) {
        return {
          statusCode: 400,
          code: "VALIDATION_ERROR",
          message: Object.values(err.errors)
            .map((e) => e.message)
            .join(", "),
        };
      }
      return null;

    case "JsonWebTokenError":
      return {
        statusCode: 401,
        code: "INVALID_TOKEN",
        message: "Your session is invalid. Please sign in again.",
      };

    case "TokenExpiredError":
      return {
        statusCode: 401,
        code: "TOKEN_EXPIRED",
        message: "Your session has expired. Please sign in again.",
      };

    case "MulterError":
      return {
        statusCode: 400,
        code: "UPLOAD_ERROR",
        message:
          err.code === "LIMIT_FILE_SIZE"
            ? "That file is too large. The maximum size is 5 MB."
            : "That file could not be uploaded.",
      };

    default:
      return null;
  }
};

/**
 * Terminal error handler.
 *
 * Contract: the response body is always { status, message, code } plus an
 * `errorId` that matches the server log line, and `details` only for
 * validation failures. Internal error text, stack traces and driver metadata
 * are logged but never sent to the client.
 */
export const error = (err, req, res, next) => {
  if (res.headersSent) return next(err);

  const errorId = randomUUID();

  const known = translateKnownError(err);
  const isApp = err instanceof AppError;

  const statusCode = known?.statusCode ?? (isApp ? err.statusCode : 500) ?? 500;
  const code = known?.code ?? (isApp ? err.code : "INTERNAL_ERROR");

  // 5xx messages are never trusted to be client-safe — they routinely carry
  // driver text, file paths or query fragments.
  const clientMessage =
    statusCode >= 500
      ? "Something went wrong on our end. Please try again."
      : known?.message ?? err.message ?? "Request failed.";

  const logPayload = {
    errorId,
    statusCode,
    code,
    method: req.method,
    path: req.originalUrl,
    userId: req.user?._id?.toString(),
    hotelId: req.user?.hotelId?.toString(),
    err,
  };

  if (statusCode >= 500) {
    logger.error(logPayload, err.message);
  } else {
    logger.warn(logPayload, err.message);
  }

  const body = {
    status: "failed",
    message: clientMessage,
    code,
    errorId,
  };

  // Field-level issues from the Zod validate() middleware are client-safe
  // and are what the form needs in order to highlight the right inputs.
  if (err.details) body.details = err.details;

  // Stack only outside production, and only ever for the developer running it.
  if (!isProduction() && statusCode >= 500) body.stack = err.stack;

  return res.status(statusCode).json(body);
};

/** 404 handler for unmatched routes — mounted just before `error`. */
export const notFound = (req, res) => {
  res.status(404).json({
    status: "failed",
    message: `Cannot ${req.method} ${req.originalUrl}`,
    code: "ROUTE_NOT_FOUND",
  });
};

export default error;
