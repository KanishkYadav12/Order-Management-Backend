import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import compression from "compression";
import mongoSanitize from "express-mongo-sanitize";
import hpp from "hpp";
import pinoHttp from "pino-http";
import mongoose from "mongoose";

import env from "../config/env.js";
import logger from "../utils/logger.js";
import { error, notFound } from "../middlewares/errorMiddleware.js";
import { ForbiddenError } from "../utils/errorHandler.js";
import { globalLimiter } from "../middlewares/security.js";

import userRouter from "../routes/userRouter.js";
import devKeyRouter from "../routes/devKeyRouter.js";
import hotelRouter from "../routes/hotelRouter.js";
import authRouter from "../routes/authRouter.js";
import tableRouter from "../routes/tableRouter.js";
import qrRouter from "../routes/qrRouter.js";
import ingredientRouter from "../routes/ingredientRouter.js";
import categoryRouter from "../routes/categoryRouter.js";
import dishRouter from "../routes/dishRouter.js";
import orderRouter from "../routes/orderRouter.js";
import billRouter from "../routes/billRouter.js";
import offerRouter from "../routes/offerRouter.js";
import utilsRouter from "../routes/utilsRouter.js";
import customerRouter from "../routes/customerRouter.js";
import dashboardRouter from "../routes/dashboardRouter.js";
import realtimeRouter from "../routes/realtimeRouter.js";
import aiRouter from "../routes/aiRouter.js";

/**
 * Builds the configured Express app.
 *
 * Kept separate from `index.js` so the app can be constructed without opening
 * a database connection — which is what makes the HTTP layer testable, and
 * what a serverless host needs in order to import the handler directly.
 *
 * @param {{ requestLogging?: boolean }} [options]
 */
export const createApp = ({ requestLogging = true } = {}) => {
  const app = express();

  app.set("trust proxy", 1);
  app.disable("x-powered-by");

  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginResourcePolicy: { policy: "cross-origin" },
    }),
  );

  /**
   * A browser's `Origin` header is scheme + host + port, never a trailing
   * slash. Pasting "https://app.example.com/" — which is what you get from a
   * browser address bar — would therefore match nothing, and every request
   * from the real app would be rejected with no clue why. Normalise instead
   * of making that a support ticket.
   */
  const allowedOrigins = new Set(
    [env.FRONTEND_URL, env.CUSTOMER_APP_URL, ...env.CORS_ORIGINS]
      .filter(Boolean)
      .map((value) => String(value).trim().replace(/\/+$/, "")),
  );

  logger.info({ allowedOrigins: [...allowedOrigins] }, "CORS allowlist");

  const corsOptions = {
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) return callback(null, true);

      /**
       * A bare `new Error` here surfaced as a 500 — the terminal handler saw
       * an unrecognised error, assumed the server had broken, and (outside
       * production) attached a stack trace to the response. A browser being
       * told "no" is not a server fault: it is a 403, and it should read as
       * one in the logs.
       */
      logger.warn({ origin }, "blocked by CORS");
      return callback(
        new ForbiddenError("This origin is not allowed to call the API.")
      );
    },
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Customer-Session"],
    credentials: true,
    maxAge: 86_400,
  };

  app.use(cors(corsOptions));
  app.options("*", cors(corsOptions));

  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: true, limit: "1mb" }));
  app.use(cookieParser());
  app.use(compression());
  app.use(mongoSanitize({ replaceWith: "_" }));
  app.use(hpp());

  if (requestLogging) {
    app.use(
      pinoHttp({
        logger,
        autoLogging: { ignore: (req) => req.url === "/health" },
        customLogLevel(_req, res, err) {
          if (err || res.statusCode >= 500) return "error";
          if (res.statusCode >= 400) return "warn";
          return "info";
        },
        serializers: {
          req: (req) => ({ method: req.method, url: req.url }),
          res: (res) => ({ statusCode: res.statusCode }),
        },
      }),
    );
  }

  app.use(globalLimiter);

  app.get("/health", (req, res) => {
    const dbUp = mongoose.connection.readyState === 1;
    res.status(dbUp ? 200 : 503).json({
      status: dbUp ? "ok" : "degraded",
      database: dbUp ? "connected" : "disconnected",
      uptime: Math.floor(process.uptime()),
    });
  });

  app.get("/", (req, res) => {
    res.json({ message: "Hotel Order Management System API", version: "v1" });
  });

  app.use("/api/v1/auth", authRouter);
  app.use("/api/v1/realtime", realtimeRouter);
  app.use("/api/v1/dashboard", dashboardRouter);
  app.use("/api/v1/ai", aiRouter);
  app.use("/api/v1/customers", customerRouter);
  app.use("/api/v1/uploads", utilsRouter);
  app.use("/api/v1/devkeys", devKeyRouter);
  app.use("/api/v1/users", userRouter);
  app.use("/api/v1/hotels", hotelRouter);
  app.use("/api/v1/tables", tableRouter);
  app.use("/api/v1/qrs", qrRouter);
  app.use("/api/v1/ingredients", ingredientRouter);
  app.use("/api/v1/categories", categoryRouter);
  app.use("/api/v1/dishes", dishRouter);
  app.use("/api/v1/orders", orderRouter);
  app.use("/api/v1/bills", billRouter);
  app.use("/api/v1/offers", offerRouter);

  app.use(notFound);
  app.use(error);

  return app;
};

export default createApp;
