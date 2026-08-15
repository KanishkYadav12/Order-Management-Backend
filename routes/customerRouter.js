import express from "express";
import { z } from "zod";
import {
  deleteDraftOrders,
  getHotelCategories,
  getHotelDishes,
  getHotelOffers,
  getHotelTable,
  getTableOrders,
} from "../controllers/customerController.js";
import { requireCustomerSession } from "../middlewares/customerSession.js";
import { customerOrderLimiter } from "../middlewares/security.js";
import { validate } from "../middlewares/validate.js";
import { objectIdParam } from "../validators/common.js";

const customerRouter = express.Router();

/**
 * QR customer app.
 *
 * Browse routes are public — they return the same menu a guest can read off
 * the table. Anything about a specific sitting requires the table session
 * issued by `POST /orders/qr-scan/:tableId`.
 */

customerRouter.get(
  "/dishes/:hotelId",
  validate({ params: objectIdParam("hotelId") }),
  getHotelDishes
);

customerRouter.get(
  "/categories/:hotelId",
  validate({ params: objectIdParam("hotelId") }),
  getHotelCategories
);

customerRouter.get(
  "/offers/:hotelId",
  validate({ params: objectIdParam("hotelId") }),
  getHotelOffers
);

customerRouter.get(
  "/table/:tableId",
  requireCustomerSession,
  validate({ params: objectIdParam("tableId") }),
  getHotelTable
);

customerRouter.get(
  "/orders/:tableId",
  requireCustomerSession,
  validate({ params: objectIdParam("tableId") }),
  getTableOrders
);

customerRouter.delete(
  "/order/:orderId",
  customerOrderLimiter,
  requireCustomerSession,
  validate({ params: objectIdParam("orderId") }),
  deleteDraftOrders
);

export default customerRouter;
