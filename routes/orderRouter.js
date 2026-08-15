import express from "express";
import {
  protect,
  attachHotelId,
  authorize,
} from "../middlewares/authMiddleware.js";
import { staffOrCustomer } from "../middlewares/staffOrCustomer.js";
import { optionalCustomerSession } from "../middlewares/customerSession.js";
import { validate } from "../middlewares/validate.js";
import { customerOrderLimiter } from "../middlewares/security.js";
import { PERMISSIONS } from "../utils/constant.js";
import {
  createOrder,
  onQRScan,
  deleteOrder,
  getOrderDetails,
  publishOrder,
  getAllOrders,
  updateStatus,
  updateOrderByOwner,
} from "../controllers/orderController.js";
import {
  createOrderSchema,
  updateOrderItemsSchema,
  orderIdSchema,
  updateStatusSchema,
  listOrdersSchema,
  tableIdParamSchema,
} from "../validators/order.js";

const router = express.Router();

/* ── Customer flow ────────────────────────────────────────────────────────
   The QR scan is the only genuinely public route. It hands back a signed
   session bound to one table, which the routes below then require. */

router.get(
  "/qr-scan/:tableId",
  customerOrderLimiter,
  validate(tableIdParamSchema),
  onQRScan
);

router.post(
  "/qr-scan/:tableId",
  customerOrderLimiter,
  validate(tableIdParamSchema),
  onQRScan
);

/** Diner with a table session, or staff taking the order at the table. */
router.post(
  "/:tableId",
  customerOrderLimiter,
  staffOrCustomer,
  validate(createOrderSchema),
  createOrder
);

router.post(
  "/publish/:orderId",
  customerOrderLimiter,
  staffOrCustomer,
  validate(orderIdSchema),
  publishOrder
);

/** Readable by the owning hotel's staff, or by the diner at that table. */
router.get(
  "/details/:orderId",
  optionalCustomerSession,
  staffOrCustomer,
  validate(orderIdSchema),
  getOrderDetails
);

/* ── Staff only ───────────────────────────────────────────────────────── */

router.get(
  "/",
  protect,
  attachHotelId,
  authorize(PERMISSIONS.ORDER_READ),
  validate(listOrdersSchema),
  getAllOrders
);

router.put(
  "/owner/:orderId",
  protect,
  attachHotelId,
  authorize(PERMISSIONS.ORDER_WRITE),
  validate(updateOrderItemsSchema),
  updateOrderByOwner
);

router.patch(
  "/:orderId/:status",
  protect,
  attachHotelId,
  authorize(PERMISSIONS.ORDER_STATUS),
  validate(updateStatusSchema),
  updateStatus
);

router.delete(
  "/:orderId",
  protect,
  attachHotelId,
  authorize(PERMISSIONS.ORDER_DELETE),
  validate(orderIdSchema),
  deleteOrder
);

export default router;
