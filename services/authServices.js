import {
  ROLES,
  isValidRole,
  SELF_SIGNUP_ROLES,
} from "../utils/constant.js";
import {
  SuperAdmin,
  HotelOwner,
  findUserByEmail,
  emailExists,
} from "../models/userModel.js";
import Hotel from "../models/hotelModel.js";
import DevKey from "../models/devKeyModel.js";
import { validateDevKey } from "../utils/validateKey.js";
import {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
} from "../utils/generateToken.js";
import {
  ClientError,
  ValidationError,
  AuthError,
  ConflictError,
  ForbiddenError,
} from "../utils/errorHandler.js";
import { sendOtpEmail } from "../utils/sendEmail.js";
import logger from "../utils/logger.js";

/** Failed attempts before the account is temporarily locked. */
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;
/** Refresh sessions retained per user; oldest is evicted beyond this. */
const MAX_SESSIONS = 5;

const modelForRole = (role) =>
  role === ROLES.SUPER_ADMIN ? SuperAdmin : HotelOwner;

/**
 * Registers a super admin or a hotel owner.
 *
 * The hotel is now created here, inside the caller's transaction. Previously
 * this block was commented out, so owners were saved with `hotelId`
 * undefined — and every tenant-scoped query then ran unscoped.
 */
export const createUserWithRole = async (
  { email, password, role, devKey, name, phone },
  session
) => {
  if (!email || !password || !name) {
    throw new ValidationError("Name, email and password are all required.");
  }

  if (!isValidRole(role) || !SELF_SIGNUP_ROLES.includes(role)) {
    throw new ValidationError(
      "Choose an account type of restaurant owner or administrator."
    );
  }

  if (await emailExists(email)) {
    throw new ConflictError("An account with that email already exists.");
  }

  // A super admin may only be created with a valid, unused dev key.
  if (role === ROLES.SUPER_ADMIN) {
    await validateDevKey(devKey, session);
  }

  const Model = modelForRole(role);

  const newUser = new Model({
    name,
    email,
    password,
    phone,
    role,
    // Super admins are trusted at creation because the dev key already proved
    // authorisation. Owners wait for approval.
    isApproved: role === ROLES.SUPER_ADMIN,
    isVerified: false,
  });

  const otp = newUser.issueOtp();

  if (role === ROLES.HOTEL_OWNER) {
    const [hotel] = await Hotel.create(
      [
        {
          name: `${name}'s Restaurant`,
          ownerId: newUser._id,
          location: "",
        },
      ],
      { session }
    );
    newUser.hotelId = hotel._id;
  }

  await newUser.save({ session });

  // Burn the dev key only once the account actually exists, so a failed
  // signup does not consume it.
  if (role === ROLES.SUPER_ADMIN) {
    await DevKey.updateOne(
      { key: devKey },
      { $set: { isUsed: true, usedAt: new Date(), usedBy: newUser._id } },
      { session }
    );
  }

  // Email is sent after the write so a mail outage cannot roll back a
  // successful registration; the user can always request a new code.
  try {
    await sendOtpEmail(email, otp, name);
  } catch (err) {
    logger.error({ err, email }, "failed to send signup OTP");
  }

  return { newUser };
};

/** Records a failed attempt and locks the account once the ceiling is hit. */
const registerFailedLogin = async (user) => {
  user.failedLoginAttempts = (user.failedLoginAttempts ?? 0) + 1;
  if (user.failedLoginAttempts >= MAX_FAILED_LOGINS) {
    user.lockedUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000);
    user.failedLoginAttempts = 0;
    logger.warn({ userId: user._id.toString() }, "account locked");
  }
  await user.save({ validateBeforeSave: false });
};

/**
 * Verifies credentials and opens a session.
 *
 * `role` is no longer used to select the collection — the previous version
 * required the client to pick the right account type, and looked in the wrong
 * collection when they got it wrong. The address alone identifies the account.
 */
export const authenticateUser = async ({ email, password, userAgent }) => {
  if (!email || !password) {
    throw new ValidationError("Enter your email and password.");
  }

  const user = await findUserByEmail(email, { withPassword: true });

  // Uniform message and shape for every rejection, so the endpoint cannot be
  // used to discover which addresses are registered.
  const invalid = () => new AuthError("That email or password is incorrect.");

  if (!user) {
    // Equalise timing against the bcrypt comparison below.
    await new Promise((resolve) => setTimeout(resolve, 120));
    throw invalid();
  }

  if (user.isLocked()) {
    throw new ClientError(
      "Too many failed attempts. Please try again in a few minutes.",
      423,
      "ACCOUNT_LOCKED"
    );
  }

  const matches = await user.matchPassword(password);
  if (!matches) {
    await registerFailedLogin(user);
    throw invalid();
  }

  if (!user.isVerified) {
    throw new ClientError(
      "Please confirm your email address before signing in.",
      403,
      "EMAIL_NOT_VERIFIED"
    );
  }

  if (user.isSuspended) {
    throw new ForbiddenError("This account has been suspended.");
  }

  if (user.role === ROLES.HOTEL_OWNER && !user.isApproved) {
    throw new ClientError(
      "Your account is awaiting approval.",
      403,
      "ACCOUNT_NOT_APPROVED"
    );
  }

  const { accessToken, refreshToken } = await issueSession(user, userAgent);

  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  user.lastLoginAt = new Date();
  await user.save({ validateBeforeSave: false });

  return { user, accessToken, refreshToken };
};

/** Mints an access/refresh pair and records the refresh session. */
export const issueSession = async (user, userAgent) => {
  const accessToken = generateAccessToken(user._id, user.role, user.hotelId);
  const { token: refreshToken, tokenId } = generateRefreshToken(
    user._id,
    user.role
  );

  user.refreshTokens = [
    ...(user.refreshTokens ?? []),
    {
      tokenHash: hashToken(tokenId),
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      userAgent: userAgent?.slice(0, 200),
    },
  ]
    .filter((session) => session.expiresAt > new Date())
    .slice(-MAX_SESSIONS);

  return { accessToken, refreshToken };
};

/**
 * Rotates a refresh token.
 *
 * The presented token is consumed and replaced. If it is not on file it has
 * either already been rotated or was forged — both mean the session is
 * compromised, so every session for that user is dropped.
 */
export const rotateRefreshSession = async (payload, userAgent) => {
  const Model = modelForRole(payload.role);
  let user = await Model.findById(payload.sub);
  if (!user) {
    const Other = Model === SuperAdmin ? HotelOwner : SuperAdmin;
    user = await Other.findById(payload.sub);
  }
  if (!user) throw new AuthError("Your session is no longer valid.");

  const presented = hashToken(payload.jti);
  const known = (user.refreshTokens ?? []).find(
    (session) => session.tokenHash === presented
  );

  if (!known) {
    logger.warn(
      { userId: user._id.toString() },
      "refresh token reuse detected — revoking all sessions"
    );
    user.refreshTokens = [];
    await user.save({ validateBeforeSave: false });
    throw new AuthError("Your session is no longer valid. Please sign in again.");
  }

  user.refreshTokens = user.refreshTokens.filter(
    (session) => session.tokenHash !== presented
  );

  const { accessToken, refreshToken } = await issueSession(user, userAgent);
  await user.save({ validateBeforeSave: false });

  return { user, accessToken, refreshToken };
};

/** Ends one session, or every session when `allDevices` is set. */
export const revokeSession = async (payload, { allDevices = false } = {}) => {
  const Model = modelForRole(payload.role);
  let user = await Model.findById(payload.sub);
  if (!user) {
    const Other = Model === SuperAdmin ? HotelOwner : SuperAdmin;
    user = await Other.findById(payload.sub);
  }
  if (!user) return;

  if (allDevices) {
    user.refreshTokens = [];
    user.tokensValidFrom = new Date();
  } else {
    const presented = hashToken(payload.jti);
    user.refreshTokens = (user.refreshTokens ?? []).filter(
      (session) => session.tokenHash !== presented
    );
  }
  await user.save({ validateBeforeSave: false });
};
