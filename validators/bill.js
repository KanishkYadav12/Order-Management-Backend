import { z } from "zod";
import { PAYMENT_METHODS, BILL_STATUS } from "../utils/constant.js";
import { objectId, objectIdParam, money, email, shortText } from "./common.js";

export const billIdSchema = { params: objectIdParam("billId") };

export const listBillsSchema = {
  query: z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(20),
    status: z.enum(Object.values(BILL_STATUS)).optional(),
    from: z.coerce.date().optional(),
    to: z.coerce.date().optional(),
    search: shortText(120).optional(),
    hotelId: objectId.optional(),
  }),
};

export const updateBillSchema = {
  params: objectIdParam("billId"),
  body: z
    .object({
      customerName: z.string().trim().min(1).max(120).optional(),
      customerEmail: email.optional().or(z.literal("")),
      customerPhone: shortText(20).optional().or(z.literal("")),
      customDiscount: z.coerce.number().min(0).optional(),
      // null clears the bill-level offer.
      globalOffer: objectId.nullable().optional().or(z.literal("")),
      notes: shortText(500).optional(),
    })
    .refine((data) => Object.keys(data).length > 0, {
      message: "Send at least one field to update.",
    }),
};

const paymentSchema = z.object({
  method: z.enum(Object.values(PAYMENT_METHODS)),
  amount: money,
  reference: shortText(80).optional(),
});

export const payBillSchema = {
  params: objectIdParam("billId"),
  body: z
    .object({
      /** One or more tenders, so a bill can be split across methods. */
      payments: z.array(paymentSchema).min(1).max(5).optional(),
      method: z.enum(Object.values(PAYMENT_METHODS)).optional(),
      customerEmail: email.optional().or(z.literal("")),
    })
    .refine((data) => data.payments?.length || data.method, {
      message: "Choose how the bill was paid.",
      path: ["method"],
    }),
};

export const voidBillSchema = {
  params: objectIdParam("billId"),
  body: z.object({
    reason: z
      .string()
      .trim()
      .min(3, "Give a short reason for voiding this bill.")
      .max(300),
  }),
};

export const sendBillSchema = {
  params: z.object({
    billId: objectId,
    email: email.optional(),
  }),
  body: z.object({ email: email.optional() }),
};
