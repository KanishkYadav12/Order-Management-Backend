import { z } from "zod";
import { ORDER_STATUS } from "../utils/constant.js";
import { objectId, objectIdParam, quantity, shortText } from "./common.js";

const orderItem = z.object({
  dishId: objectId,
  quantity,
  note: shortText(200).optional().or(z.literal("")),
  /** The existing clients send `notes`; accepted and normalised downstream. */
  notes: shortText(200).optional().or(z.literal("")),
});

export const createOrderSchema = {
  params: objectIdParam("tableId"),
  body: z.object({
    customerName: z.string().trim().min(1).max(80).optional(),
    dishes: z.array(orderItem).min(1, "Add at least one dish.").max(60),
    note: shortText(500).optional().or(z.literal("")),
    status: z.enum([ORDER_STATUS.DRAFT, ORDER_STATUS.PENDING]).optional(),
    customerSession: z.string().optional(),
  }),
};

export const updateOrderItemsSchema = {
  params: objectIdParam("orderId"),
  body: z.object({
    dishes: z.array(orderItem).min(1, "An order needs at least one dish.").max(60),
  }),
};

export const orderIdSchema = { params: objectIdParam("orderId") };

export const updateStatusSchema = {
  params: z.object({
    orderId: objectId,
    status: z.enum(Object.values(ORDER_STATUS), {
      message: "That is not a valid order status.",
    }),
  }),
};

export const listOrdersSchema = {
  query: z.object({
    status: z.enum(Object.values(ORDER_STATUS)).optional(),
    tableId: objectId.optional(),
    activeOnly: z.enum(["true", "false"]).optional(),
    hotelId: objectId.optional(),
  }),
};

export const tableIdParamSchema = { params: objectIdParam("tableId") };
