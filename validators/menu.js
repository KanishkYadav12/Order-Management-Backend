import { z } from "zod";
import {
  objectId,
  objectIdParam,
  money,
  percentage,
  shortText,
  longText,
  optionalUrl,
} from "./common.js";

/* ── Dishes ───────────────────────────────────────────────────────────── */

const dishBody = z.object({
  name: z.string().trim().min(3, "Use at least 3 characters.").max(100),
  price: money,
  category: objectId,
  description: longText(500).optional().or(z.literal("")),
  logo: optionalUrl,
  ingredients: z.array(objectId).max(50).optional(),
  preparationTime: z
    .string()
    .trim()
    .regex(
      /^\d+\s*(minutes?|mins?)$/i,
      'Write preparation time like "15 minutes".'
    )
    .optional()
    .or(z.literal("")),
  bestSeller: z.boolean().optional(),
  outOfStock: z.boolean().optional(),
  // Tax rate for this dish; falls back to the hotel default when omitted.
  taxRatePercent: percentage.optional(),
  isVegetarian: z.boolean().optional(),
  spiceLevel: z.enum(["none", "mild", "medium", "hot"]).optional(),
});

export const createDishSchema = { body: dishBody };

export const updateDishSchema = {
  params: objectIdParam("dishId"),
  // Partial, but never empty — an empty PATCH is almost always a client bug.
  body: dishBody.partial().refine((data) => Object.keys(data).length > 0, {
    message: "Send at least one field to update.",
  }),
};

export const dishIdSchema = { params: objectIdParam("dishId") };

export const dishStockSchema = {
  params: objectIdParam("dishId"),
  body: z.object({ outOfStock: z.boolean() }),
};

export const listDishesSchema = {
  query: z.object({
    search: shortText(120).optional(),
    category: objectId.optional(),
    includeDeleted: z.enum(["true", "false"]).optional(),
    hotelId: objectId.optional(), // super-admin scoping
  }),
};

/* ── Categories ───────────────────────────────────────────────────────── */

const categoryBody = z.object({
  name: z.string().trim().min(2, "Use at least 2 characters.").max(60),
  description: longText(300).optional().or(z.literal("")),
  logo: optionalUrl,
  /** Controls menu ordering on the customer app. */
  displayOrder: z.number().int().min(0).max(999).optional(),
});

export const createCategorySchema = { body: categoryBody };

export const createMultipleCategoriesSchema = {
  body: z.object({
    categories: z.array(categoryBody).min(1).max(50),
  }),
};

export const updateCategorySchema = {
  params: objectIdParam("categoryId"),
  body: categoryBody.partial().refine((d) => Object.keys(d).length > 0, {
    message: "Send at least one field to update.",
  }),
};

export const categoryIdSchema = { params: objectIdParam("categoryId") };

export const deleteMultipleCategoriesSchema = {
  body: z.object({ categoryIds: z.array(objectId).min(1).max(50) }),
};

/* ── Ingredients ──────────────────────────────────────────────────────── */

const ingredientBody = z.object({
  name: z.string().trim().min(2, "Use at least 2 characters.").max(60),
  description: longText(300).optional().or(z.literal("")),
  logo: optionalUrl,
  /** Stock tracking, all optional so existing records stay valid. */
  unit: z.enum(["g", "kg", "ml", "l", "piece", "packet"]).optional(),
  stockQuantity: z.number().min(0).optional(),
  lowStockThreshold: z.number().min(0).optional(),
  costPerUnit: money.optional(),
});

export const createIngredientSchema = { body: ingredientBody };

export const createMultipleIngredientsSchema = {
  body: z.object({ ingredients: z.array(ingredientBody).min(1).max(100) }),
};

export const updateIngredientSchema = {
  params: objectIdParam("ingredientId"),
  body: ingredientBody.partial().refine((d) => Object.keys(d).length > 0, {
    message: "Send at least one field to update.",
  }),
};

export const ingredientIdSchema = { params: objectIdParam("ingredientId") };

/* ── Offers ───────────────────────────────────────────────────────────── */

const offerBody = z
  .object({
    name: z.string().trim().min(2).max(80),
    type: z.enum(["specific", "global"]),
    discountType: z.enum(["percent", "amount"]),
    value: z.number().min(0, "Cannot be negative."),
    appliedOn: z.array(objectId).max(200).optional(),
    appliedAbove: money.optional(),
    description: longText(300).optional().or(z.literal("")),
    logo: optionalUrl,
    disable: z.boolean().optional(),
    startDate: z.coerce.date().optional(),
    endDate: z.coerce.date().optional(),
  })
  .refine(
    (data) => data.discountType !== "percent" || data.value <= 100,
    { message: "A percentage discount cannot exceed 100%.", path: ["value"] }
  )
  .refine(
    (data) => !data.startDate || !data.endDate || data.endDate > data.startDate,
    { message: "The end date must come after the start date.", path: ["endDate"] }
  )
  .refine(
    (data) => data.type !== "specific" || (data.appliedOn?.length ?? 0) > 0,
    { message: "Choose at least one dish for this offer.", path: ["appliedOn"] }
  );

export const createOfferSchema = { body: offerBody };
export const offerIdSchema = { params: objectIdParam("id") };
export const updateOfferSchema = {
  params: objectIdParam("id"),
  body: offerBody,
};

/* ── Tables ───────────────────────────────────────────────────────────── */

const tableBody = z.object({
  sequence: z.number().int().min(1, "Table number must be 1 or more.").max(999),
  capacity: z.number().int().min(1, "Seats at least 1.").max(50),
  position: shortText(60).optional().or(z.literal("")),
  status: z.enum(["free", "occupied", "reserved", "cleaning"]).optional(),
});

export const createTableSchema = { body: tableBody };

export const updateTableSchema = {
  params: objectIdParam("tableId"),
  body: tableBody.partial().refine((d) => Object.keys(d).length > 0, {
    message: "Send at least one field to update.",
  }),
};

export const tableIdSchema = { params: objectIdParam("tableId") };
