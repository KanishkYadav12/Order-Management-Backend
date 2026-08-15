import express from "express";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  getOfferDetails,
  updateOffer,
  deleteOffer,
  createOffer,
  getAllOffers,
} from "../controllers/offerController.js";
import {
  createOfferSchema,
  updateOfferSchema,
  offerIdSchema,
} from "../validators/menu.js";

const router = express.Router();

router.use(protect, attachHotelId);

router.get("/", authorize(PERMISSIONS.MENU_READ), getAllOffers);

router.post(
  "/",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(createOfferSchema),
  createOffer
);

router.get(
  "/:id",
  authorize(PERMISSIONS.MENU_READ),
  validate(offerIdSchema),
  getOfferDetails
);

router.put(
  "/:id",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(updateOfferSchema),
  updateOffer
);

router.delete(
  "/:id",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(offerIdSchema),
  deleteOffer
);

export default router;
