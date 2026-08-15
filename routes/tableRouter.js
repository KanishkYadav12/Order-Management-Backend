import express from "express";
import { protect, attachHotelId, authorize } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  getTableById,
  getTables,
  createTable,
  updateTable,
  deleteTable,
  getOrdersByTable,
  generateTableBill,
  getCustomerDetails,
} from "../controllers/tableController.js";
import {
  createTableSchema,
  updateTableSchema,
  tableIdSchema,
} from "../validators/menu.js";

const router = express.Router();

router.use(protect, attachHotelId);

router.get("/", authorize(PERMISSIONS.TABLE_READ), getTables);

router.post(
  "/",
  authorize(PERMISSIONS.TABLE_WRITE),
  validate(createTableSchema),
  createTable
);

/* Literal prefixes come first so they are not captured by `/:tableId`. */
router.get(
  "/bill/:tableId",
  authorize(PERMISSIONS.BILL_WRITE),
  validate(tableIdSchema),
  generateTableBill
);

router.get(
  "/orders/:tableId",
  authorize(PERMISSIONS.ORDER_READ),
  validate(tableIdSchema),
  getOrdersByTable
);

/** Retained: the dashboard already calls this path for a table's orders. */
router.get(
  "/table/:tableId",
  authorize(PERMISSIONS.ORDER_READ),
  validate(tableIdSchema),
  getOrdersByTable
);

router.get(
  "/get-customer/:tableId",
  authorize(PERMISSIONS.TABLE_READ),
  validate(tableIdSchema),
  getCustomerDetails
);

router.get(
  "/:tableId",
  authorize(PERMISSIONS.TABLE_READ),
  validate(tableIdSchema),
  getTableById
);

router.put(
  "/:tableId",
  authorize(PERMISSIONS.TABLE_WRITE),
  validate(updateTableSchema),
  updateTable
);

router.delete(
  "/:tableId",
  authorize(PERMISSIONS.TABLE_WRITE),
  validate(tableIdSchema),
  deleteTable
);

export default router;
