import express from "express";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  createDish,
  getAllDishes,
  getDishById,
  getDishesByCategory,
  updateDish,
  deleteDish,
  removeOfferFromDish,
  setDishStock,
} from "../controllers/dishController.js";
import {
  createDishSchema,
  updateDishSchema,
  dishIdSchema,
  dishStockSchema,
  listDishesSchema,
  categoryIdSchema,
} from "../validators/menu.js";

const router = express.Router();

/**
 * Every route resolves the tenant through `attachHotelId`, and the services
 * below fold that hotel id into the query itself — so there is no path where
 * a dish from another restaurant can be reached.
 */
router.use(protect, attachHotelId);

router.get(
  "/",
  authorize(PERMISSIONS.MENU_READ),
  validate(listDishesSchema),
  getAllDishes
);

router.post(
  "/",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(createDishSchema),
  createDish
);

router.get(
  "/category/:categoryId",
  authorize(PERMISSIONS.MENU_READ),
  validate(categoryIdSchema),
  getDishesByCategory
);

router.get(
  "/:dishId",
  authorize(PERMISSIONS.MENU_READ),
  validate(dishIdSchema),
  getDishById
);

router.patch(
  "/:dishId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(updateDishSchema),
  updateDish
);

/** Stock toggle is a floor action, so chefs and waiters can reach it. */
router.patch(
  "/:dishId/stock",
  authorize(PERMISSIONS.MENU_READ),
  validate(dishStockSchema),
  setDishStock
);

router.delete(
  "/:dishId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(dishIdSchema),
  deleteDish
);

router.put(
  "/remove-offer/:dishId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(dishIdSchema),
  removeOfferFromDish
);

export default router;
