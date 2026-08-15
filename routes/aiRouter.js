import express from "express";
import { z } from "zod";
import {
  protect,
  attachHotelId,
  authorize,
} from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { aiLimiter } from "../middlewares/security.js";
import { PERMISSIONS } from "../utils/constant.js";
import { objectId, objectIdParam, dateRange } from "../validators/common.js";
import {
  getAiStatus,
  getMenuAnalysis,
  getForecast,
  getPrepPlan,
  getPairings,
  getAnomalies,
  getBriefing,
  askAssistant,
  generateDishDescription,
  getUpsellSuggestions,
} from "../controllers/aiController.js";

const router = express.Router();

/**
 * Insight endpoints.
 *
 * The analytics routes (menu, forecast, prep, pairings, anomalies) are
 * deterministic calculations over the restaurant's own data — no external
 * service, no cost, no rate limit beyond the app's own. Only `ask`,
 * `briefing` and `describe` call a language model, and each degrades
 * gracefully when none is configured.
 */

/** Public: the QR menu asks for pairings while a diner builds their order. */
router.get(
  "/upsell/:hotelId",
  validate({
    params: objectIdParam("hotelId"),
    query: z.object({ dishes: z.string().max(500).optional() }),
  }),
  getUpsellSuggestions
);

router.use(protect, attachHotelId);

router.get("/status", getAiStatus);

/* ── Deterministic analytics ──────────────────────────────────────────── */

router.get(
  "/menu-analysis",
  authorize(PERMISSIONS.REPORT_READ),
  validate({ query: dateRange.extend({ hotelId: objectId.optional() }) }),
  getMenuAnalysis
);

router.get(
  "/forecast",
  authorize(PERMISSIONS.REPORT_READ),
  validate({
    query: z.object({
      days: z.coerce.number().int().min(1).max(30).optional(),
      hotelId: objectId.optional(),
    }),
  }),
  getForecast
);

router.get(
  "/prep-plan",
  authorize(PERMISSIONS.MENU_READ),
  validate({
    query: z.object({
      date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
      hotelId: objectId.optional(),
    }),
  }),
  getPrepPlan
);

router.get("/pairings", authorize(PERMISSIONS.REPORT_READ), getPairings);
router.get("/anomalies", authorize(PERMISSIONS.REPORT_READ), getAnomalies);

/* ── Language-model backed ────────────────────────────────────────────── */

router.get(
  "/briefing",
  authorize(PERMISSIONS.DASHBOARD_READ),
  aiLimiter,
  getBriefing
);

router.post(
  "/ask",
  authorize(PERMISSIONS.AI_USE),
  aiLimiter,
  validate({
    body: z.object({
      question: z
        .string()
        .trim()
        .min(3, "Ask a question first.")
        .max(500, "That question is too long."),
    }),
  }),
  askAssistant
);

router.post(
  "/describe/:dishId",
  authorize(PERMISSIONS.MENU_WRITE),
  aiLimiter,
  validate({ params: objectIdParam("dishId") }),
  generateDishDescription
);

export default router;
