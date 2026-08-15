import express from "express";
import { z } from "zod";
import {
  getUserProfile,
  approveHotelOwner,
  getAllHotelOwners,
  getUnApprovedOwners,
  getApprovedOwners,
  membershipExtender,
  deleteHotelOwner,
  updateOwner,
  sendMailForMembershipExpired,
} from "../controllers/userController.js";
import {
  protect,
  superAdminOnly,
  attachHotelId,
  authorize,
} from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { emailLimiter } from "../middlewares/security.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  objectIdParam,
  personName,
  phone,
  optionalUrl,
  pagination,
} from "../validators/common.js";

const router = express.Router();

const updateProfileSchema = {
  body: z
    .object({
      name: personName.optional(),
      phone: phone.optional(),
      logo: optionalUrl,
      gender: z.enum(["M", "F", "O"]).optional(),
    })
    .refine((data) => Object.keys(data).length > 0, {
      message: "Send at least one field to update.",
    }),
};

const extendSchema = {
  params: objectIdParam("hotelOwnerId"),
  body: z.object({
    days: z.coerce
      .number()
      .int("Enter a whole number of days.")
      .min(0)
      .max(3650),
  }),
};

/* ── Self ─────────────────────────────────────────────────────────────── */

router.get("/profile", protect, getUserProfile);

/**
 * Updates the caller's own profile. The `:ownerId` segment is ignored and
 * kept only so the existing dashboard's URL still resolves — the previous
 * handler already ignored it, but read the body straight into the model.
 */
router.patch(
  "/owner/:ownerId",
  protect,
  validate(updateProfileSchema),
  updateOwner
);

/* ── Platform administration ──────────────────────────────────────────── */

router.get(
  "/hotel-owners/pending-approval",
  protect,
  superAdminOnly,
  validate({ query: pagination }),
  getUnApprovedOwners
);

router.get(
  "/hotel-owners/approved",
  protect,
  superAdminOnly,
  validate({ query: pagination }),
  getApprovedOwners
);

router.get(
  "/hotel-owners",
  protect,
  superAdminOnly,
  validate({ query: pagination }),
  getAllHotelOwners
);

router.patch(
  "/approve-hotel-owner/:ownerId",
  protect,
  superAdminOnly,
  approveHotelOwner
);

router.delete(
  "/hotel-owner/:ownerId",
  protect,
  superAdminOnly,
  deleteHotelOwner
);

router.patch(
  "/membership-extender/:hotelOwnerId",
  protect,
  superAdminOnly,
  validate(extendSchema),
  membershipExtender
);

router.get(
  "/send-email-membership-expired/:hotelOwnerId",
  protect,
  superAdminOnly,
  emailLimiter,
  sendMailForMembershipExpired
);

export default router;
