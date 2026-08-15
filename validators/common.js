import { z } from "zod";
import mongoose from "mongoose";

/** A Mongo ObjectId, as it arrives from a URL parameter or a JSON body. */
export const objectId = z
  .string()
  .refine((value) => mongoose.isValidObjectId(value), {
    message: "That id is not valid.",
  });

export const objectIdParam = (key) => z.object({ [key]: objectId });

export const email = z
  .string()
  .trim()
  .toLowerCase()
  .min(1, "Enter your email address.")
  .email("That doesn't look like a valid email address.");

/**
 * Password policy.
 *
 * Length carries most of the strength, so the floor is 8 with a character-mix
 * requirement rather than a long list of rules that pushes people toward
 * "Password1!".
 */
export const password = z
  .string()
  .min(8, "Use at least 8 characters.")
  .max(128, "That password is too long.")
  .refine((value) => /[a-z]/.test(value), {
    message: "Include at least one lowercase letter.",
  })
  .refine((value) => /[A-Z]/.test(value), {
    message: "Include at least one uppercase letter.",
  })
  .refine((value) => /\d/.test(value), {
    message: "Include at least one number.",
  });

export const personName = z
  .string()
  .trim()
  .min(2, "Enter a name of at least 2 characters.")
  .max(120, "That name is too long.");

export const phone = z
  .string()
  .trim()
  .regex(/^[+]?[\d\s()-]{7,20}$/, "Enter a valid phone number.")
  .optional()
  .or(z.literal(""));

export const optionalUrl = z
  .string()
  .trim()
  .url("Enter a valid URL.")
  .optional()
  .or(z.literal(""));

/** Money, in the smallest sensible unit for the market: whole rupees + paise. */
export const money = z
  .number()
  .min(0, "Cannot be negative.")
  .max(10_000_000, "That amount is too large.")
  .refine((value) => Number.isFinite(value), { message: "Enter a number." });

export const quantity = z
  .number()
  .int("Enter a whole number.")
  .min(1, "Quantity must be at least 1.")
  .max(999, "That quantity is too large.");

export const percentage = z
  .number()
  .min(0, "Cannot be negative.")
  .max(100, "Cannot be more than 100%.");

/** Standard list controls, with bounds so a client cannot request everything. */
export const pagination = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sort: z.string().trim().max(64).optional(),
  order: z.enum(["asc", "desc"]).default("desc"),
  search: z.string().trim().max(120).optional(),
});

export const dateRange = z.object({
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
});

/** Trimmed, length-capped free text. */
export const shortText = (max = 200) => z.string().trim().max(max);
export const longText = (max = 2000) => z.string().trim().max(max);
