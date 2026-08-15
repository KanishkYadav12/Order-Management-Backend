import express from "express";
import {
  signUp,
  login,
  refresh,
  logout,
  verifyEmail,
  resendOtp,
  forgotPassword,
  resetPassword,
  changePassword,
  me,
} from "../controllers/authController.js";
import { protect } from "../middlewares/authMiddleware.js";
import { validate } from "../middlewares/validate.js";
import {
  authLimiter,
  otpLimiter,
  emailLimiter,
} from "../middlewares/security.js";
import {
  signUpSchema,
  loginSchema,
  verifyEmailSchema,
  resendOtpSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from "../validators/auth.js";

const router = express.Router();

/* ── Public ───────────────────────────────────────────────────────────── */

router.post("/signup", authLimiter, validate(signUpSchema), signUp);
router.post("/login", authLimiter, validate(loginSchema), login);

/** Exchanges the httpOnly refresh cookie for a new access token. */
router.post("/refresh", refresh);
router.post("/logout", logout);

router.post("/verify", otpLimiter, validate(verifyEmailSchema), verifyEmail);
router.post("/resend-otp", emailLimiter, validate(resendOtpSchema), resendOtp);

router.post(
  "/forgot-password",
  emailLimiter,
  validate(forgotPasswordSchema),
  forgotPassword
);
router.post(
  "/reset-password/:token",
  authLimiter,
  validate(resetPasswordSchema),
  resetPassword
);

/**
 * Aliases for the paths the dashboard was already calling. These previously
 * returned 404 because no such routes existed, which is why the forgot-password
 * and change-password screens failed.
 */
router.post(
  "/send-reset-password-email",
  emailLimiter,
  validate(forgotPasswordSchema),
  forgotPassword
);

/* ── Authenticated ────────────────────────────────────────────────────── */

router.get("/me", protect, me);
router.post(
  "/change-password",
  protect,
  validate(changePasswordSchema),
  changePassword
);

export default router;
