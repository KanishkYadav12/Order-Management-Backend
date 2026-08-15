import mongoose from "mongoose";
import env from "../config/env.js";
import logger from "../utils/logger.js";
import connectDb from "../connectDb.js";
import { createApp } from "./app.js";

const app = createApp();

const start = async () => {
  await connectDb(env.DATABASE_URL);

  const server = app.listen(env.PORT, () => {
    logger.info(
      { port: env.PORT, env: env.NODE_ENV, ai: env.aiEnabled },
      `API listening on port ${env.PORT}`
    );
  });

  /** Drains in-flight requests before exiting so a deploy doesn't sever them. */
  const shutdown = (signal) => {
    logger.info({ signal }, "shutting down");
    server.close(async () => {
      await mongoose.connection.close(false);
      process.exit(0);
    });
    // Hard stop if a connection refuses to drain.
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));

  process.on("unhandledRejection", (reason) => {
    logger.error({ err: reason }, "unhandled promise rejection");
  });
  process.on("uncaughtException", (err) => {
    logger.fatal({ err }, "uncaught exception — exiting");
    process.exit(1);
  });
};

start().catch((err) => {
  logger.fatal({ err }, "failed to start");
  process.exit(1);
});

export default app;
