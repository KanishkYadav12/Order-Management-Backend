import { z } from "zod";
import { SELF_SIGNUP_ROLES } from "../utils/constant.js";
import { email, password, personName, phone } from "./common.js";

export const signUpSchema = {
  body: z
    .object({
      name: personName,
      email,
      password,
      role: z.enum(SELF_SIGNUP_ROLES),
      phone: phone.optional(),
      devKey: z.string().trim().min(1).optional(),
    })
    // A super admin can only be created with a dev key; catching it here
    // gives a field-level error instead of a generic rejection deeper in.
    .refine((data) => data.role !== "superadmin" || Boolean(data.devKey), {
      message: "An administrator account requires a valid dev key.",
      path: ["devKey"],
    }),
};

export const loginSchema = {
  body: z.object({
    email,
    password: z.string().min(1, "Enter your password."),
    // Accepted for backward compatibility with the existing dashboard form,
    // but no longer used to select the account — the email identifies it.
    role: z.string().optional(),
  }),
};

export const verifyEmailSchema = {
  body: z.object({
    email,
    otp: z
      .string()
      .trim()
      .regex(/^\d{6}$/, "Enter the 6-digit code from your email.")
      .or(z.coerce.string().trim().regex(/^\d{6}$/)),
  }),
};

export const resendOtpSchema = {
  body: z.object({ email }),
};

export const forgotPasswordSchema = {
  body: z.object({ email }),
};

export const resetPasswordSchema = {
  params: z.object({
    token: z.string().trim().length(64, "That reset link is not valid."),
  }),
  body: z.object({ password }),
};

export const changePasswordSchema = {
  body: z
    .object({
      currentPassword: z.string().min(1, "Enter your current password."),
      newPassword: password,
    })
    .refine((data) => data.currentPassword !== data.newPassword, {
      message: "Your new password must be different from the current one.",
      path: ["newPassword"],
    }),
};

