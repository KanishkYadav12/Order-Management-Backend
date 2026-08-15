import express from "express";
import { z } from "zod";
import {
  getIngredientById,
  createIngredient,
  updateIngredient,
  deleteIngredient,
  getIngredientsByHotel,
  getLowStockIngredients,
  syncIngredientsFromSourceToDestination,
  createMultipleIngredients,
} from "../controllers/ingredientController.js";
import {
  protect,
  attachHotelId,
  superAdminOnly,
  authorize,
} from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import { objectId } from "../validators/common.js";
import {
  createIngredientSchema,
  createMultipleIngredientsSchema,
  updateIngredientSchema,
  ingredientIdSchema,
} from "../validators/menu.js";

const router = express.Router();

const syncSchema = {
  body: z.object({ source: objectId, destination: objectId }),
};

/**
 * Cross-tenant copy. Declared before `router.use(attachHotelId)` because it
 * deliberately operates on two hotels, neither of which is the caller's.
 */
router.post(
  "/sync",
  protect,
  superAdminOnly,
  validate(syncSchema),
  syncIngredientsFromSourceToDestination
);

router.use(protect, attachHotelId);

router.get("/", authorize(PERMISSIONS.MENU_READ), getIngredientsByHotel);
router.get(
  "/low-stock",
  authorize(PERMISSIONS.MENU_READ),
  getLowStockIngredients
);

router.post(
  "/",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(createIngredientSchema),
  createIngredient
);

router.post(
  "/multiple",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(createMultipleIngredientsSchema),
  createMultipleIngredients
);

router.get(
  "/:ingredientId",
  authorize(PERMISSIONS.MENU_READ),
  validate(ingredientIdSchema),
  getIngredientById
);

router.patch(
  "/:ingredientId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(updateIngredientSchema),
  updateIngredient
);

router.delete(
  "/:ingredientId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(ingredientIdSchema),
  deleteIngredient
);

export default router;
