import express from "express";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  createCategory,
  createMultipleCategories,
  deleteCategory,
  deleteMultipleCategories,
  getAllCategories,
  getCategoryById,
  updateCategory,
} from "../controllers/categoryController.js";
import {
  createCategorySchema,
  createMultipleCategoriesSchema,
  updateCategorySchema,
  categoryIdSchema,
  deleteMultipleCategoriesSchema,
} from "../validators/menu.js";

const router = express.Router();

router.use(protect, attachHotelId);

router.get("/", authorize(PERMISSIONS.MENU_READ), getAllCategories);

router.post(
  "/",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(createCategorySchema),
  createCategory
);

/* Literal paths are declared before `/:categoryId` so they are not swallowed
   by the parameterised route. */
router.post(
  "/multiple",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(createMultipleCategoriesSchema),
  createMultipleCategories
);

router.delete(
  "/multiple",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(deleteMultipleCategoriesSchema),
  deleteMultipleCategories
);

router.get(
  "/:categoryId",
  authorize(PERMISSIONS.MENU_READ),
  validate(categoryIdSchema),
  getCategoryById
);

router.patch(
  "/:categoryId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(updateCategorySchema),
  updateCategory
);

router.delete(
  "/:categoryId",
  authorize(PERMISSIONS.MENU_WRITE),
  validate(categoryIdSchema),
  deleteCategory
);

export default router;
