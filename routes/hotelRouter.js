import express from "express";
import { z } from "zod";
import {
  protect,
  superAdminOnly,
  authorize,
} from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  updateHotel,
  deleteHotel,
  getHotelById,
  getMyHotel,
  getAllHotels,
} from "../controllers/hotelController.js";
import {
  objectIdParam,
  shortText,
  longText,
  optionalUrl,
  percentage,
  email,
  phone,
  pagination,
} from "../validators/common.js";

const router = express.Router();

const updateHotelSchema = {
  params: objectIdParam("hotelId"),
  body: z.object({
    name: shortText(120).optional(),
    location: shortText(300).optional(),
    description: longText(1000).optional(),
    phone: phone.optional(),
    email: email.optional().or(z.literal("")),
    logo: optionalUrl,
    banner: optionalUrl,
    billing: z
      .object({
        gstin: z
          .string()
          .trim()
          .toUpperCase()
          .regex(
            /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]$/,
            "That doesn't look like a valid GSTIN."
          )
          .optional()
          .or(z.literal("")),
        taxRatePercent: percentage.optional(),
        pricesIncludeTax: z.boolean().optional(),
        serviceChargePercent: percentage.optional(),
        currency: z.string().trim().length(3).optional(),
        currencySymbol: z.string().trim().max(3).optional(),
        roundOffEnabled: z.boolean().optional(),
        invoicePrefix: z.string().trim().max(8).optional(),
        footerNote: shortText(300).optional(),
      })
      .optional(),
    serviceHours: z
      .object({
        opensAt: z.string().regex(/^\d{2}:\d{2}$/).optional(),
        closesAt: z.string().regex(/^\d{2}:\d{2}$/).optional(),
        acceptingOrders: z.boolean().optional(),
      })
      .optional(),
  }),
};

/**
 * Literal routes are declared before `/:hotelId`.
 *
 * `GET /getAllHotels` previously sat after the parameterised route, so Express
 * matched `/:hotelId` first and the literal path was unreachable.
 */
router.get(
  "/getAllHotels",
  protect,
  superAdminOnly,
  validate({ query: pagination }),
  getAllHotels
);

router.get("/me", protect, getMyHotel);

router.get("/:hotelId", protect, getHotelById);

router.put(
  "/:hotelId",
  protect,
  authorize(PERMISSIONS.HOTEL_SETTINGS),
  validate(updateHotelSchema),
  updateHotel
);

router.delete("/:hotelId", protect, superAdminOnly, deleteHotel);

export default router;
