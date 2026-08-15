import express from "express";
import { printQr } from "../controllers/qrController.js";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import { tableIdSchema } from "../validators/menu.js";

const router = express.Router();

router.get(
  "/:tableId",
  protect,
  attachHotelId,
  authorize(PERMISSIONS.TABLE_READ),
  validate(tableIdSchema),
  printQr
);

export default router;
