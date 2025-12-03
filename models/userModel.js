import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

/**
 * Base schema for all users.
 * Contains shared fields + password & reset token logic.
 */
const userBaseSchema = new mongoose.Schema(
  {
    logo: {
      type: String,
    },

    gender: {
      type: String,
      enum: ["M", "F", "O"],
      default: "M",
    },

    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
    },

    phone: {
      type: String,
      required: false, // fixed: require → required
    },

    password: {
      type: String,
      required: true,
    },

    role: {
      type: String,
      required: true, // e.g., "superadmin", "hotelowner"
    },

    hotelId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Hotel",
    },

    isApproved: {
      type: Boolean,
      default: false,
    },

    isVerified: {
      type: Boolean,
      default: false, // for email verification
    },

    otpDetails: {
      value: {
        type: Number,
        default: null,
      },
      expiry: {
        type: Date,
        default: null,
      },
    },

    membershipExpires: {
      type: Date,
      default: null,
    },

    passwordResettoken: {
      type: String,
      default: null,
    },

    passwordResetExpires: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true, // adds createdAt & updatedAt
  }
);

/**
 * Hash password before saving.
 */
userBaseSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

/**
 * Compare plain text password with hashed password.
 */
userBaseSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

/**
 * Generate secure password reset token.
 * - Returns plain token for sending to user.
 * - Stores hashed version in DB.
 */
userBaseSchema.methods.createPasswordResettoken = function () {
  const resettoken = crypto.randomBytes(32).toString("hex");

  this.passwordResettoken = crypto
    .createHash("sha256")
    .update(resettoken)
    .digest("hex");

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

  return resettoken; // send this to user
};

/**
 * Validate a submitted password reset token.
 */
userBaseSchema.methods.validatePasswordResettoken = function (submittedtoken) {
  if (!this.passwordResettoken || !this.passwordResetExpires) return false;

  // expired?
  if (this.passwordResetExpires < Date.now()) return false;

  const hashedtoken = crypto
    .createHash("sha256")
    .update(submittedtoken)
    .digest("hex");

  return this.passwordResettoken === hashedtoken;
};

/**
 * MODELS
 * Base User + cloned schemas for SuperAdmin & HotelOwner
 * (Separate collections, not discriminators)
 */

const User = mongoose.model("User", userBaseSchema);

const SuperAdminSchema = userBaseSchema.clone();
const SuperAdmin = mongoose.model(
  "SuperAdmin",
  SuperAdminSchema,
  "superadmins"
);

const HotelOwnerSchema = userBaseSchema.clone();
const HotelOwner = mongoose.model(
  "HotelOwner",
  HotelOwnerSchema,
  "hotelowners"
);

export { User, SuperAdmin, HotelOwner };
