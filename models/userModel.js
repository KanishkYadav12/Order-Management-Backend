import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { ROLES } from "../utils/constant.js";

/** Work factor for bcrypt. 12 is the current sensible default for a web app. */
const BCRYPT_ROUNDS = 12;

const userBaseSchema = new mongoose.Schema(
  {
    logo: { type: String },

    gender: {
      type: String,
      enum: ["M", "F", "O"],
      default: "M",
    },

    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },

    phone: { type: String, trim: true },

    password: {
      type: String,
      required: true,
      // Never returned by default. Explicitly re-selected by the login path,
      // so a stray `.find()` can't leak hashes into a response body.
      select: false,
    },

    role: {
      type: String,
      required: true,
      enum: Object.values(ROLES),
      index: true,
    },

    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
      index: true,
    },

    isApproved: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false },

    /** Set by an owner or admin to revoke access without deleting the record. */
    isSuspended: { type: Boolean, default: false },

    otpDetails: {
      /** SHA-256 of the code. The plaintext is emailed and never stored. */
      hash: { type: String, default: null },
      expiry: { type: Date, default: null },
      attempts: { type: Number, default: 0 },
    },

    membershipExpires: { type: Date, default: null },

    passwordResettoken: { type: String, default: null },
    passwordResetExpires: { type: Date, default: null },

    /**
     * Hashed jti of every live refresh token, so a session can be revoked
     * individually and a stolen token can be invalidated without forcing a
     * password change.
     */
    refreshTokens: [
      {
        tokenHash: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
        expiresAt: { type: Date, required: true },
        userAgent: { type: String },
      },
    ],

    /**
     * Any access token issued before this instant is rejected. Bumped on
     * password change and on "sign out everywhere".
     */
    tokensValidFrom: { type: Date, default: Date.now },

    lastLoginAt: { type: Date },
    /** Consecutive failed logins, for lockout. */
    failedLoginAttempts: { type: Number, default: 0 },
    lockedUntil: { type: Date, default: null },

    /** Who invited this staff member, for the audit trail. */
    invitedBy: { type: mongoose.Schema.Types.ObjectId },
  },
  { timestamps: true }
);

/* Staff lists are always read per hotel and per role. */
userBaseSchema.index({ hotelId: 1, role: 1 });
userBaseSchema.index({ isApproved: 1, role: 1 });

/* ── Password handling ────────────────────────────────────────────────── */

userBaseSchema.pre("save", async function hashPassword(next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, BCRYPT_ROUNDS);

  // Changing a password invalidates every previously issued token.
  if (!this.isNew) {
    this.tokensValidFrom = new Date();
    this.refreshTokens = [];
  }
  next();
});

userBaseSchema.methods.matchPassword = async function matchPassword(entered) {
  if (!this.password) return false;
  return bcrypt.compare(entered, this.password);
};

/** True while the account is temporarily locked after repeated failures. */
userBaseSchema.methods.isLocked = function isLocked() {
  return Boolean(this.lockedUntil && this.lockedUntil > new Date());
};

/* ── One-time passcodes ───────────────────────────────────────────────── */

/**
 * Issues a 6-digit code. Uses crypto.randomInt rather than Math.random, and
 * stores only a hash — the previous implementation kept the code in plaintext
 * on the document with no attempt counter.
 */
userBaseSchema.methods.issueOtp = function issueOtp() {
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
  this.otpDetails = {
    hash: crypto.createHash("sha256").update(code).digest("hex"),
    expiry: new Date(Date.now() + 10 * 60 * 1000),
    attempts: 0,
  };
  return code;
};

/** Constant-time comparison so the check cannot be timed. */
userBaseSchema.methods.verifyOtp = function verifyOtp(submitted) {
  const { hash, expiry } = this.otpDetails ?? {};
  if (!hash || !expiry || expiry < new Date()) return false;

  const submittedHash = crypto
    .createHash("sha256")
    .update(String(submitted))
    .digest("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(submittedHash, "hex")
  );
};

userBaseSchema.methods.clearOtp = function clearOtp() {
  this.otpDetails = { hash: null, expiry: null, attempts: 0 };
};

/* ── Password reset ───────────────────────────────────────────────────── */

userBaseSchema.methods.createPasswordResettoken =
  function createPasswordResettoken() {
    const resetToken = crypto.randomBytes(32).toString("hex");
    this.passwordResettoken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    this.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);
    return resetToken;
  };

userBaseSchema.methods.clearPasswordReset = function clearPasswordReset() {
  this.passwordResettoken = null;
  this.passwordResetExpires = null;
};

/* ── Serialisation ────────────────────────────────────────────────────── */

/** Strips every secret from anything that reaches a response body. */
userBaseSchema.set("toJSON", {
  transform(_doc, ret) {
    delete ret.password;
    delete ret.otpDetails;
    delete ret.passwordResettoken;
    delete ret.passwordResetExpires;
    delete ret.refreshTokens;
    delete ret.failedLoginAttempts;
    delete ret.lockedUntil;
    delete ret.__v;
    return ret;
  },
});

/**
 * MODELS
 *
 * Two collections, not discriminators:
 *   superadmins — platform staff
 *   hotelowners — every tenant user (owner, manager, cashier, chef, waiter),
 *                 distinguished by `role`
 *
 * The collection name predates staff roles; `TenantUser` is the accurate name
 * for what it now holds and is the alias new code should import.
 */
const SuperAdmin = mongoose.model(
  "SuperAdmin",
  userBaseSchema.clone(),
  "superadmins"
);

const HotelOwner = mongoose.model(
  "HotelOwner",
  userBaseSchema.clone(),
  "hotelowners"
);

/**
 * Finds a user by email across both collections.
 *
 * Replaces the previous `User.findOne({ email })`, which queried a third,
 * always-empty `users` collection — so the duplicate-email check at signup
 * never actually matched anything.
 */
export const findUserByEmail = async (email, { withPassword = false } = {}) => {
  const normalised = String(email ?? "").toLowerCase().trim();
  if (!normalised) return null;

  const projection = withPassword ? "+password" : "";
  const admin = await SuperAdmin.findOne({ email: normalised }).select(projection);
  if (admin) return admin;
  return HotelOwner.findOne({ email: normalised }).select(projection);
};

/** True if the address is taken in either collection. */
export const emailExists = async (email) =>
  Boolean(await findUserByEmail(email));

export { SuperAdmin, HotelOwner };
export const TenantUser = HotelOwner;
export const User = HotelOwner;
