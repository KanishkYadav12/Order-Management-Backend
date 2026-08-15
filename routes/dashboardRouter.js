import express from "express";
import { getDashboardStats } from "../controllers/dashboardController.js";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import { dateRange } from "../validators/common.js";
import { z } from "zod";
import { objectId } from "../validators/common.js";

const router = express.Router();

router.get(
  "/",
  protect,
  attachHotelId,
  authorize(PERMISSIONS.DASHBOARD_READ),
  validate({ query: dateRange.extend({ hotelId: objectId.optional() }) }),
  getDashboardStats
);

export default router;
