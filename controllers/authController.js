import crypto from "crypto";
import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import {
  SuperAdmin,
  HotelOwner,
  findUserByEmail,
} from "../models/userModel.js";
import {
  createUserWithRole,
  authenticateUser,
  rotateRefreshSession,
  revokeSession,
  issueSession,
} from "../services/authServices.js";
import {
  verifyRefreshToken,
  refreshCookieName,
  refreshCookieOptions,
} from "../utils/generateToken.js";
import { sendOtpEmail, sendPasswordResetEmail } from "../utils/sendEmail.js";
import { ClientError, AuthError } from "../utils/errorHandler.js";
import env from "../config/env.js";
import logger from "../utils/logger.js";

/** Maximum OTP guesses before the code is burned and must be re-requested. */
const MAX_OTP_ATTEMPTS = 5;

/**
 * Public shape of a user. Keys match what the dashboard already reads, so the
 * existing client keeps working unchanged.
 */
const publicUser = (user, accessToken) => ({
  id: user._id,
  name: user.name,
  role: user.role,
  email: user.email,
  hotelId: user.hotelId ?? null,
  isVerified: user.isVerified,
  isApproved: user.isApproved,
  ...(accessToken ? { token: accessToken, accessToken } : {}),
});

/**
 * Account-recovery endpoints always answer the same way whether or not the
 * address is registered. Anything else is a user-enumeration oracle.
 */
const NEUTRAL_RECOVERY_RESPONSE = {
  status: "success",
  message:
    "If an account exists for that address, we've sent it an email. Check your inbox.",
};

export const signUp = catchAsyncError(async (req, res, next, session) => {
  const { newUser } = await createUserWithRole(req.body, session);

  res.status(201).json({
    status: "success",
    message:
      "Account created. Check your email for the 6-digit code to confirm your address.",
    data: publicUser(newUser),
  });
}, true);

export const login = catchAsyncError(async (req, res) => {
  const { email, password } = req.body;

  const { user, accessToken, refreshToken } = await authenticateUser({
    email,
    password,
    userAgent: req.headers["user-agent"],
  });

  // Long-lived credential goes in an httpOnly cookie the page cannot read;
  // only the short-lived access token is handed to JavaScript.
  res.cookie(refreshCookieName, refreshToken, refreshCookieOptions());

  res.status(200).json({
    status: "success",
    message: "Signed in",
    data: publicUser(user, accessToken),
  });
});

/** Exchanges the refresh cookie for a fresh access token, rotating the cookie. */
export const refresh = catchAsyncError(async (req, res) => {
  const token = req.cookies?.[refreshCookieName];
  if (!token) throw new AuthError("Please sign in again.");

  let payload;
  try {
    payload = verifyRefreshToken(token);
  } catch {
    res.clearCookie(refreshCookieName, refreshCookieOptions());
    throw new AuthError("Your session has expired. Please sign in again.");
  }

  const { user, accessToken, refreshToken } = await rotateRefreshSession(
    payload,
    req.headers["user-agent"]
  );

  res.cookie(refreshCookieName, refreshToken, refreshCookieOptions());

  res.status(200).json({
    status: "success",
    message: "Session refreshed",
    data: publicUser(user, accessToken),
  });
});

export const logout = catchAsyncError(async (req, res) => {
  const token = req.cookies?.[refreshCookieName];

  if (token) {
    try {
      await revokeSession(verifyRefreshToken(token), {
        allDevices: Boolean(req.body?.allDevices),
      });
    } catch (err) {
      // An unparseable token is already useless — clearing the cookie is
      // still the right outcome, so this is not surfaced.
      logger.debug({ err }, "logout with invalid refresh token");
    }
  }

  res.clearCookie(refreshCookieName, refreshCookieOptions());
  res.status(200).json({ status: "success", message: "Signed out" });
});

export const verifyEmail = catchAsyncError(async (req, res) => {
  const { email, otp } = req.body;

  const user = await findUserByEmail(email);
  if (!user) {
    throw new ClientError("That code is not valid.", 400, "INVALID_OTP");
  }

  if (user.isVerified) {
    return res.status(200).json({
      status: "success",
      message: "Your email is already confirmed. You can sign in.",
    });
  }

  if ((user.otpDetails?.attempts ?? 0) >= MAX_OTP_ATTEMPTS) {
    user.clearOtp();
    await user.save({ validateBeforeSave: false });
    throw new ClientError(
      "Too many incorrect attempts. Request a new code.",
      429,
      "OTP_ATTEMPTS_EXCEEDED"
    );
  }

  if (!user.verifyOtp(otp)) {
    user.otpDetails.attempts = (user.otpDetails?.attempts ?? 0) + 1;
    await user.save({ validateBeforeSave: false });
    throw new ClientError(
      "That code is incorrect or has expired.",
      400,
      "INVALID_OTP"
    );
  }

  user.isVerified = true;
  user.clearOtp();
  await user.save({ validateBeforeSave: false });

  res.status(200).json({
    status: "success",
    message: "Email confirmed. You can sign in now.",
  });
});

export const resendOtp = catchAsyncError(async (req, res) => {
  const { email } = req.body;
  const user = await findUserByEmail(email);

  // Neutral response regardless of whether the account exists or is already
  // verified — the same reasoning as password reset.
  if (user && !user.isVerified) {
    const code = user.issueOtp();
    await user.save({ validateBeforeSave: false });
    await sendOtpEmail(user.email, code, user.name);
  }

  res.status(200).json({
    status: "success",
    message:
      "If that address needs confirming, we've sent a new code. Check your inbox.",
  });
});

export const forgotPassword = catchAsyncError(async (req, res) => {
  const { email } = req.body;
  const user = await findUserByEmail(email);

  if (user) {
    const resetToken = user.createPasswordResettoken();
    await user.save({ validateBeforeSave: false });

    // Built from configuration. This used to be a hardcoded URL pointing at a
    // different deployment entirely, so reset links never reached this app.
    const resetUrl = `${env.FRONTEND_URL.replace(/\/$/, "")}/reset-password/${resetToken}`;
    await sendPasswordResetEmail(user.email, resetUrl, user.name);
  }

  res.status(200).json(NEUTRAL_RECOVERY_RESPONSE);
});

export const resetPassword = catchAsyncError(async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  const hashed = crypto.createHash("sha256").update(token).digest("hex");
  const query = {
    passwordResettoken: hashed,
    passwordResetExpires: { $gt: new Date() },
  };

  const user =
    (await SuperAdmin.findOne(query)) ?? (await HotelOwner.findOne(query));

  if (!user) {
    throw new ClientError(
      "That reset link has expired. Request a new one.",
      400,
      "RESET_TOKEN_INVALID"
    );
  }

  user.password = password;
  user.clearPasswordReset();
  // The pre-save hook bumps tokensValidFrom and drops refresh sessions, so
  // every device is signed out when the password changes.
  await user.save();

  res.status(200).json({
    status: "success",
    message: "Password updated. You can sign in with your new password.",
  });
});

export const changePassword = catchAsyncError(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const Model = req.user.role === "superadmin" ? SuperAdmin : HotelOwner;
  const user = await Model.findById(req.user._id).select("+password");
  if (!user) throw new AuthError("Please sign in again.");

  if (!(await user.matchPassword(currentPassword))) {
    throw new ClientError(
      "Your current password is incorrect.",
      400,
      "INCORRECT_PASSWORD"
    );
  }

  user.password = newPassword;
  await user.save();

  // Every session is now invalid, including this one — issue a new pair so
  // the user is not bounced to the login screen after changing a password.
  const { accessToken, refreshToken } = await issueSession(
    user,
    req.headers["user-agent"]
  );
  await user.save({ validateBeforeSave: false });

  res.cookie(refreshCookieName, refreshToken, refreshCookieOptions());

  res.status(200).json({
    status: "success",
    message: "Password updated.",
    data: publicUser(user, accessToken),
  });
});

/** Returns the signed-in user — used by the dashboard to rehydrate on load. */
export const me = catchAsyncError(async (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Profile loaded",
    data: { user: req.user },
  });
});
