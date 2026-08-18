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
  dishFacts,
  approveDishFacts,
  publicDishFacts,
  chatWithAdvisor,
  listConversations,
  getConversation,
  deleteConversation,
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

/**
 * Public: the write-up a diner reads before ordering.
 *
 * Read-only and approved-only by design — generation is an owner action, so a
 * table session can never be used to spend the restaurant's AI quota.
 */
router.get(
  "/dish-facts/:hotelId/:dishId",
  validate({
    params: z.object({ hotelId: objectId, dishId: objectId }),
  }),
  publicDishFacts
);

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

/* ── Advisor chat ─────────────────────────────────────────────────────
   Stateful, tool-calling, and aware of the calendar and local news. The
   `/ask` route above stays as the stateless single-report version. */

router.post(
  "/chat",
  authorize(PERMISSIONS.AI_USE),
  aiLimiter,
  validate({
    body: z.object({
      message: z
        .string()
        .trim()
        .min(2, "Ask something first.")
        .max(1000, "That message is too long."),
      conversationId: objectId.optional(),
    }),
  }),
  chatWithAdvisor
);

/* Owner-side generation and sign-off for dish write-ups. */
router.post(
  "/dish-facts/:dishId",
  authorize(PERMISSIONS.MENU_WRITE),
  aiLimiter,
  validate({
    params: objectIdParam("dishId"),
    query: z.object({ force: z.enum(["true", "false"]).optional() }),
  }),
  dishFacts
);

router.patch(
  "/dish-facts/:dishId/approval",
  authorize(PERMISSIONS.MENU_WRITE),
  validate({
    params: objectIdParam("dishId"),
    body: z.object({ approved: z.boolean() }),
  }),
  approveDishFacts
);

router.get("/conversations", authorize(PERMISSIONS.AI_USE), listConversations);

router.get(
  "/conversations/:conversationId",
  authorize(PERMISSIONS.AI_USE),
  validate({ params: objectIdParam("conversationId") }),
  getConversation
);

router.delete(
  "/conversations/:conversationId",
  authorize(PERMISSIONS.AI_USE),
  validate({ params: objectIdParam("conversationId") }),
  deleteConversation
);

export default router;
