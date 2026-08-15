import mongoose from "mongoose";
import { supportsTransactions } from "../connectDb.js";
import logger from "../utils/logger.js";

/**
 * Wraps an async route handler so rejections reach the error middleware.
 *
 * @param {Function} handler  (req, res, next, session) => Promise<void>
 * @param {boolean}  withTransaction
 *   Opens a MongoDB session and transaction around the handler. Use this only
 *   for handlers that write more than one document and need all-or-nothing
 *   semantics — a session on a read-only handler is pure overhead.
 *
 *   Transactions require a replica set. On a standalone mongod the handler
 *   still runs, with `session` as null, rather than failing outright; every
 *   query in this codebase passes the session through optionally, so this
 *   degrades to individual writes instead of breaking the route.
 */
export const catchAsyncError =
  (handler, withTransaction = false) =>
  async (req, res, next) => {
    const useTransaction = withTransaction && supportsTransactions();

    if (withTransaction && !useTransaction) {
      logger.warn(
        { path: req.originalUrl },
        "transactions unavailable (no replica set) — running without atomicity"
      );
    }

    if (!useTransaction) {
      try {
        await handler(req, res, next, null);
      } catch (err) {
        next(err);
      }
      return;
    }

    const session = await mongoose.startSession();
    try {
      session.startTransaction();
      await handler(req, res, next, session);

      // If the handler already responded with a failure, or delegated to
      // next(err), committing would persist a write the client was told
      // failed. Abort in that case.
      if (res.statusCode >= 400) {
        await session.abortTransaction();
      } else {
        await session.commitTransaction();
      }
    } catch (err) {
      if (session.inTransaction()) {
        await session.abortTransaction().catch((abortErr) => {
          logger.error({ err: abortErr }, "failed to abort transaction");
        });
      }
      next(err);
    } finally {
      await session.endSession();
    }
  };

export default catchAsyncError;
