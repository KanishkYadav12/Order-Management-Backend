import express from "express";
import {
  getStaffRealtimeToken,
  getCustomerRealtimeToken,
} from "../controllers/realtimeController.js";
import { protect } from "../middlewares/authMiddleware.js";
import { requireCustomerSession } from "../middlewares/customerSession.js";

const router = express.Router();

/**
 * Realtime credentials.
 *
 * These replace the hardcoded Ably key that used to ship in the browser
 * bundle. Each caller receives a token scoped to exactly one channel, with
 * subscribe-only capability — publishing stays server-side.
 */
router.post("/token", protect, getStaffRealtimeToken);
router.post(
  "/customer-token/:tableId",
  requireCustomerSession,
  getCustomerRealtimeToken
);

export default router;
